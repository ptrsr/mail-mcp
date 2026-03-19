//! Microsoft Graph API client for sending emails
//!
//! Uses the Microsoft Graph REST API (`POST /me/sendMail`) to send emails
//! from Microsoft accounts (personal and enterprise). This bypasses SMTP
//! entirely, which is necessary for personal hotmail/outlook.com accounts
//! where Microsoft has disabled SMTP AUTH.
//!
//! # Requirements
//!
//! - OAuth2 configured with `provider=microsoft`
//! - Token scope must include `https://graph.microsoft.com/Mail.Send`
//!
//! # Configuration
//!
//! Uses the same `MAIL_OAUTH2_<SEGMENT>_*` variables as IMAP/SMTP OAuth2.
//! No additional configuration needed beyond OAuth2.

use serde::Serialize;

use crate::errors::{AppError, AppResult};
use crate::oauth2::TokenManager;

/// Microsoft Graph API base URL
const GRAPH_API_BASE: &str = "https://graph.microsoft.com/v1.0";

// ─── Request types ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SendMailRequest {
    message: GraphMessage,
    save_to_sent_items: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphMessage {
    subject: String,
    body: GraphBody,
    to_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cc_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bcc_recipients: Vec<GraphRecipient>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<Vec<GraphRecipient>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    internet_message_headers: Option<Vec<GraphHeader>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<GraphAttachment>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphBody {
    content_type: &'static str,
    content: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphRecipient {
    email_address: GraphEmailAddress,
}

#[derive(Debug, Serialize)]
struct GraphEmailAddress {
    address: String,
}

#[derive(Debug, Serialize)]
struct GraphHeader {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphAttachment {
    #[serde(rename = "@odata.type")]
    odata_type: &'static str,
    name: String,
    content_type: String,
    content_bytes: String,
}

// ─── Helper constructors ─────────────────────────────────────────────────────

fn recipient(addr: &str) -> GraphRecipient {
    GraphRecipient {
        email_address: GraphEmailAddress {
            address: addr.to_owned(),
        },
    }
}

fn recipients(addrs: &[String]) -> Vec<GraphRecipient> {
    addrs.iter().map(|a| recipient(a)).collect()
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Parameters for sending an email via Microsoft Graph
/// An attachment for Graph API
pub struct GraphEmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub content_base64: String,
}

/// Parameters for sending an email via Microsoft Graph
pub struct GraphEmailParams {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: String,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub reply_to: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub attachments: Vec<GraphEmailAttachment>,
    pub save_to_sent: bool,
}

/// Send an email using the Microsoft Graph API.
///
/// Calls `POST /me/sendMail` with the provided parameters.
/// Requires an OAuth2 token with `Mail.Send` scope.
///
/// # Errors
///
/// - `AuthFailed` if the token is invalid or lacks permissions
/// - `InvalidInput` if email addresses are malformed (caught by Graph API)
/// - `Internal` for network or API errors
pub async fn send_email(
    token_manager: &TokenManager,
    account_id: &str,
    params: &GraphEmailParams,
) -> AppResult<()> {
    let access_token = token_manager.get_access_token(account_id).await?;

    let (content_type, content) = match (&params.body_html, &params.body_text) {
        (Some(html), _) => ("HTML", sanitize_cdata(html)),
        (None, Some(text)) => ("Text", sanitize_cdata(text)),
        (None, None) => ("Text", String::new()),
    };

    let mut headers = Vec::new();
    if let Some(ref refs) = params.references {
        headers.push(GraphHeader {
            name: "References".to_owned(),
            value: refs.clone(),
        });
    }

    let message = GraphMessage {
        subject: params.subject.clone(),
        body: GraphBody {
            content_type,
            content,
        },
        to_recipients: recipients(&params.to),
        cc_recipients: recipients(&params.cc),
        bcc_recipients: recipients(&params.bcc),
        reply_to: params
            .reply_to
            .as_ref()
            .map(|addr| vec![recipient(addr)]),
        in_reply_to: params.in_reply_to.clone(),
        internet_message_headers: if headers.is_empty() {
            None
        } else {
            Some(headers)
        },
        attachments: params
            .attachments
            .iter()
            .map(|a| GraphAttachment {
                odata_type: "#microsoft.graph.fileAttachment",
                name: a.filename.clone(),
                content_type: a.content_type.clone(),
                content_bytes: a.content_base64.clone(),
            })
            .collect(),
    };

    let request_body = SendMailRequest {
        message,
        save_to_sent_items: params.save_to_sent,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{GRAPH_API_BASE}/me/sendMail"))
        .bearer_auth(&access_token)
        .json(&request_body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| AppError::Internal(format!("Graph API request failed: {e}")))?;

    if response.status().is_success() {
        // 202 Accepted is the expected response
        Ok(())
    } else {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if status.as_u16() == 401 || status.as_u16() == 403 {
            Err(AppError::AuthFailed(format!(
                "Graph API authentication failed ({status}): {body}"
            )))
        } else {
            Err(AppError::Internal(format!(
                "Graph API sendMail failed ({status}): {body}"
            )))
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Remove CDATA artifacts that some email clients leak into text.
fn sanitize_cdata(text: &str) -> String {
    text.replace("]]>", "").replace("<![CDATA[", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_builds_correct_structure() {
        let r = recipient("test@example.com");
        assert_eq!(r.email_address.address, "test@example.com");
    }

    #[test]
    fn recipients_builds_list() {
        let addrs = vec!["a@b.com".to_owned(), "c@d.com".to_owned()];
        let rs = recipients(&addrs);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].email_address.address, "a@b.com");
    }

    #[test]
    fn send_mail_request_serializes_correctly() {
        let req = SendMailRequest {
            message: GraphMessage {
                subject: "Test".to_owned(),
                body: GraphBody {
                    content_type: "Text",
                    content: "Hello".to_owned(),
                },
                to_recipients: vec![recipient("to@test.com")],
                cc_recipients: vec![],
                bcc_recipients: vec![],
                reply_to: None,
                in_reply_to: None,
                internet_message_headers: None,
                attachments: vec![],
            },
            save_to_sent_items: true,
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["message"]["subject"], "Test");
        assert_eq!(json["message"]["body"]["contentType"], "Text");
        assert_eq!(json["message"]["toRecipients"][0]["emailAddress"]["address"], "to@test.com");
        assert_eq!(json["saveToSentItems"], true);
        // cc and bcc should be absent (skip_serializing_if)
        assert!(json["message"].get("ccRecipients").is_none());
    }
}
