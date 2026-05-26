// ContractShield Email Subscribe API
// POST /api/subscribe — captures email, stores in DynamoDB, sends welcome email via AWS SES
// Env vars required: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION

export const config = { runtime: "nodejs" };

import crypto from "crypto";

const CHECKLIST_URL =
  "https://contractshield.co/assets/freelance-contract-checklist.pdf";
const EMAIL_FROM = "ContractShield <noreply@contractshield.co>";
const SITE_URL = "https://contractshield.co";

const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;

// ── AWS SigV4 ────────────────────────────────────────────────────────────────

function hmacSha256(key, data, encoding) {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest(encoding);
}

function sha256Hex(data) {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}

function makeSigningKey(secretKey, date, region, service) {
  const kDate = hmacSha256("AWS4" + secretKey, date);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

function awsSignedHeaders({ host, service, body, contentType }) {
  const now = new Date();
  const amzdate = now.toISOString().replace(/[:\-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  const datestamp = amzdate.slice(0, 8);
  const payloadHash = sha256Hex(body);

  const canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${host}\n` +
    `x-amz-date:${amzdate}\n`;
  const signedHeaders = "content-type;host;x-amz-date";

  const canonicalRequest = ["POST", "/", "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const credentialScope = `${datestamp}/${AWS_REGION}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzdate, credentialScope, sha256Hex(canonicalRequest)].join("\n");

  const signingKey = makeSigningKey(AWS_SECRET_ACCESS_KEY, datestamp, AWS_REGION, service);
  const signature = hmacSha256(signingKey, stringToSign, "hex");
  const authHeader = `AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return {
    "Content-Type": contentType,
    "X-Amz-Date": amzdate,
    Authorization: authHeader,
  };
}

// ── DynamoDB helpers ─────────────────────────────────────────────────────────

async function dynamodbPut(email) {
  const host = `dynamodb.${AWS_REGION}.amazonaws.com`;
  const body = JSON.stringify({
    TableName: "contractshield-subscribers",
    Item: {
      email: { S: email },
      subscribed_at: { N: String(Date.now()) },
      email1_sent: { BOOL: true },
      email2_sent: { BOOL: false },
      email3_sent: { BOOL: false },
    },
    ConditionExpression: "attribute_not_exists(email)",
  });

  const headers = awsSignedHeaders({ host, service: "dynamodb", body, contentType: "application/x-amz-json-1.0" });
  headers["X-Amz-Target"] = "DynamoDB_20120810.PutItem";

  const res = await fetch(`https://${host}/`, { method: "POST", headers, body });
  if (!res.ok) {
    const text = await res.text();
    if (text.includes("ConditionalCheckFailedException")) return { alreadyExists: true };
    throw new Error(`DynamoDB PutItem failed: ${text}`);
  }
  return { alreadyExists: false };
}

// ── SES helper ───────────────────────────────────────────────────────────────

async function sendSESEmail({ to, from, subject, htmlBody, textBody }) {
  const host = `email.${AWS_REGION}.amazonaws.com`;
  const params = new URLSearchParams({
    Action: "SendEmail",
    Source: from,
    "Destination.ToAddresses.member.1": to,
    "Message.Subject.Data": subject,
    "Message.Subject.Charset": "UTF-8",
    "Message.Body.Html.Data": htmlBody,
    "Message.Body.Html.Charset": "UTF-8",
    "Message.Body.Text.Data": textBody || subject,
    "Message.Body.Text.Charset": "UTF-8",
  });
  const body = params.toString();

  const headers = awsSignedHeaders({ host, service: "ses", body, contentType: "application/x-www-form-urlencoded" });

  const res = await fetch(`https://${host}/`, { method: "POST", headers, body });
  const text = await res.text();
  if (!res.ok) throw new Error(`SES SendEmail failed (${res.status}): ${text}`);
  return text;
}

// ── Email 1 template ─────────────────────────────────────────────────────────

function email1HTML() {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Your Free Contract Checklist</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Inter',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.07);">
  <tr><td style="background:linear-gradient(135deg,#1e40af,#3b82f6);padding:32px 40px;text-align:center;">
    <div style="font-size:28px;margin-bottom:8px;">&#x1F6E1;</div>
    <div style="color:#fff;font-size:20px;font-weight:800;letter-spacing:-0.02em;">ContractShield</div>
    <div style="color:rgba(255,255,255,0.7);font-size:13px;margin-top:4px;">contractshield.co</div>
  </td></tr>
  <tr><td style="padding:40px;">
    <p style="margin:0 0 20px;font-size:16px;color:#1e293b;line-height:1.6;">Hey!</p>
    <p style="margin:0 0 20px;font-size:16px;color:#475569;line-height:1.6;">
      Here's your <strong style="color:#1e293b;">Free Freelance Contract Checklist</strong> &#8212; 10 clauses to check before you sign anything.
    </p>
    <p style="margin:0 0 28px;font-size:16px;color:#475569;line-height:1.6;">
      I put this together after seeing hundreds of freelancers get burned by the same contract traps: vague payment terms, unlimited revisions, IP that transfers before they get paid...
    </p>
    <table cellpadding="0" cellspacing="0" style="margin:0 auto 28px;">
      <tr><td style="background:#1e40af;border-radius:10px;">
        <a href="${CHECKLIST_URL}" style="display:block;padding:16px 36px;color:#fff;font-size:16px;font-weight:700;text-decoration:none;">
          Download Your Checklist &#8594;
        </a>
      </td></tr>
    </table>
    <div style="background:#eff6ff;border-left:4px solid #1e40af;border-radius:0 8px 8px 0;padding:20px 24px;margin-bottom:28px;">
      <p style="margin:0 0 12px;font-size:14px;font-weight:700;color:#1e40af;">Quick preview &#8212; top 3 most-missed clauses:</p>
      <p style="margin:0 0 8px;font-size:14px;color:#1e293b;">&#10003; <strong>Kill fee</strong> &#8212; if the client cancels, you still get paid for work done</p>
      <p style="margin:0 0 8px;font-size:14px;color:#1e293b;">&#10003; <strong>IP transfer on payment</strong> &#8212; they get the files when you get the money</p>
      <p style="margin:0;font-size:14px;color:#1e293b;">&#10003; <strong>Revision cap</strong> &#8212; "unlimited revisions" = unlimited unpaid work</p>
    </div>
    <p style="margin:0 0 8px;font-size:15px;color:#475569;line-height:1.6;">
      Tomorrow I'll share a real story about a $2,800 ghosting case &#8212; and exactly which contract clause would have prevented it.
    </p>
    <p style="margin:0;font-size:15px;color:#475569;">Talk soon,<br><strong style="color:#1e293b;">Matteo</strong><br><span style="color:#94a3b8;font-size:13px;">Founder, ContractShield</span></p>
  </td></tr>
  <tr><td style="background:#f8fafc;padding:24px 40px;border-top:1px solid #e2e8f0;text-align:center;">
    <p style="margin:0 0 8px;font-size:13px;color:#94a3b8;">
      You're getting this because you signed up at <a href="${SITE_URL}" style="color:#6366f1;">contractshield.co</a>.
    </p>
    <p style="margin:0;font-size:12px;color:#cbd5e1;">&#169; 2026 ContractShield</p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

// ── Main handler ─────────────────────────────────────────────────────────────

export default async function handler(req, res) {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  let body;
  try {
    body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
  } catch {
    return res.status(400).json({ error: "Invalid JSON" });
  }

  const email = (body?.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ error: "Valid email required" });
  }

  if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
    console.error("AWS credentials not configured");
    return res.status(500).json({ error: "Email service not configured" });
  }

  try {
    // 1. Store in DynamoDB (email1_sent defaults to true since we send it now)
    const { alreadyExists } = await dynamodbPut(email);
    if (alreadyExists) {
      return res.status(200).json({ success: true, message: "You're already subscribed!" });
    }

    // 2. Send Email 1 immediately (checklist)
    await sendSESEmail({
      to: email,
      from: EMAIL_FROM,
      subject: "Your free contract checklist is here",
      htmlBody: email1HTML(),
      textBody: `Your Free Freelance Contract Checklist is ready!\n\nDownload it here: ${CHECKLIST_URL}\n\nTomorrow I'll share a real story about a $2,800 ghosting case.\n\nTalk soon,\nMatteo\nFounder, ContractShield`,
    });

    return res.status(200).json({ success: true, message: "Check your inbox!" });
  } catch (err) {
    console.error("Subscribe error:", err);
    return res.status(500).json({ error: "Failed to subscribe. Please try again." });
  }
}
