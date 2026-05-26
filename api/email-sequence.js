// ContractShield Email Sequence Cron
// GET /api/email-sequence — runs daily via Vercel cron at 0 10 * * *
// Sends Email 2 (~day 2) and Email 3 (~day 4) to eligible subscribers
// Env vars: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, CRON_SECRET

export const config = { runtime: "nodejs" };

import crypto from "crypto";

const EMAIL_FROM = "ContractShield <noreply@contractshield.co>";
const SITE_URL = "https://contractshield.co";
const STRIPE_LINK = "https://buy.stripe.com/dRmbJ2dUMaLU1w59tVcjS00";

const AWS_REGION = process.env.AWS_REGION || "us-east-1";
const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;
const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;
const CRON_SECRET = process.env.CRON_SECRET;

const TABLE = "contractshield-subscribers";

// ── SigV4 ──────────────────────────────────────────────────────────────────

function hmac(key, data, enc) {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest(enc);
}
function sha256(data) {
  return crypto.createHash("sha256").update(data, "utf8").digest("hex");
}
function signingKey(secret, date, region, service) {
  return hmac(hmac(hmac(hmac("AWS4" + secret, date), region), service), "aws4_request");
}
function signedHeaders({ host, service, body, contentType, target }) {
  const now = new Date();
  const ts = now.toISOString().replace(/[:\-]|\.\d{3}/g, "").slice(0, 15) + "Z";
  const ds = ts.slice(0, 8);
  const ph = sha256(body);
  const ch = `content-type:${contentType}\nhost:${host}\nx-amz-date:${ts}\n`;
  const sh = "content-type;host;x-amz-date";
  const cr = ["POST", "/", "", ch, sh, ph].join("\n");
  const scope = `${ds}/${AWS_REGION}/${service}/aws4_request`;
  const sts = ["AWS4-HMAC-SHA256", ts, scope, sha256(cr)].join("\n");
  const sig = hmac(signingKey(AWS_SECRET_ACCESS_KEY, ds, AWS_REGION, service), sts, "hex");
  const auth = `AWS4-HMAC-SHA256 Credential=${AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${sh}, Signature=${sig}`;
  const h = { "Content-Type": contentType, "X-Amz-Date": ts, Authorization: auth };
  if (target) h["X-Amz-Target"] = target;
  return h;
}

// ── DynamoDB ───────────────────────────────────────────────────────────────

async function dynamoScan() {
  const host = `dynamodb.${AWS_REGION}.amazonaws.com`;
  const body = JSON.stringify({ TableName: TABLE });
  const headers = signedHeaders({
    host, service: "dynamodb", body,
    contentType: "application/x-amz-json-1.0",
    target: "DynamoDB_20120810.Scan",
  });
  const res = await fetch(`https://${host}/`, { method: "POST", headers, body });
  const data = await res.json();
  if (!res.ok) throw new Error(`DynamoDB Scan: ${JSON.stringify(data)}`);
  return data.Items || [];
}

async function dynamoUpdate(email, field) {
  const host = `dynamodb.${AWS_REGION}.amazonaws.com`;
  const body = JSON.stringify({
    TableName: TABLE,
    Key: { email: { S: email } },
    UpdateExpression: `SET ${field} = :t`,
    ExpressionAttributeValues: { ":t": { BOOL: true } },
  });
  const headers = signedHeaders({
    host, service: "dynamodb", body,
    contentType: "application/x-amz-json-1.0",
    target: "DynamoDB_20120810.UpdateItem",
  });
  const res = await fetch(`https://${host}/`, { method: "POST", headers, body });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`DynamoDB UpdateItem: ${t}`);
  }
}

// ── SES ────────────────────────────────────────────────────────────────────

async function sendEmail({ to, subject, html, text }) {
  const host = `email.${AWS_REGION}.amazonaws.com`;
  const params = new URLSearchParams({
    Action: "SendEmail",
    Source: EMAIL_FROM,
    "Destination.ToAddresses.member.1": to,
    "Message.Subject.Data": subject,
    "Message.Subject.Charset": "UTF-8",
    "Message.Body.Html.Data": html,
    "Message.Body.Html.Charset": "UTF-8",
    "Message.Body.Text.Data": text || subject,
    "Message.Body.Text.Charset": "UTF-8",
  });
  const body = params.toString();
  const headers = signedHeaders({ host, service: "ses", body, contentType: "application/x-www-form-urlencoded" });
  const res = await fetch(`https://${host}/`, { method: "POST", headers, body });
  const t = await res.text();
  if (!res.ok) throw new Error(`SES SendEmail (${res.status}): ${t}`);
  return t;
}

// ── Email 2 — Ghost Client Story ───────────────────────────────────────────

function email2HTML() {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>The $2,800 Ghost Client</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Inter',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.07);">
  <tr><td style="background:linear-gradient(135deg,#1e40af,#3b82f6);padding:28px 40px;text-align:center;">
    <div style="color:#fff;font-size:18px;font-weight:800;">ContractShield</div>
    <div style="color:rgba(255,255,255,0.7);font-size:12px;">contractshield.co</div>
  </td></tr>
  <tr><td style="padding:40px;">
    <p style="margin:0 0 20px;font-size:22px;font-weight:800;color:#1e293b;line-height:1.3;">The $2,800 Ghost Client</p>
    <p style="margin:0 0 20px;font-size:16px;color:#475569;line-height:1.7;">
      Marcus spent 3 weeks building a website for a small e-commerce business. Great communication throughout. Then&hellip; silence.
    </p>
    <p style="margin:0 0 20px;font-size:16px;color:#475569;line-height:1.7;">
      No reply to emails. No answer to calls. The client had the completed site files Marcus sent for "final review" &#8212; and disappeared with $2,800 worth of work.
    </p>
    <div style="background:#fef2f2;border-left:4px solid #ef4444;border-radius:0 8px 8px 0;padding:20px 24px;margin-bottom:24px;">
      <p style="margin:0;font-size:15px;font-weight:700;color:#dc2626;">What went wrong:</p>
      <p style="margin:8px 0 0;font-size:14px;color:#7f1d1d;line-height:1.6;">
        His "contract" was a 2-line email that said "I'll build your site for $2,800." No IP transfer clause. No payment milestone. No kill fee.
      </p>
    </div>
    <p style="margin:0 0 16px;font-size:16px;color:#475569;line-height:1.7;">
      One clause would have saved him: <strong style="color:#1e293b;">"Deliverables remain the intellectual property of the contractor until payment is received in full."</strong>
    </p>
    <p style="margin:0 0 24px;font-size:16px;color:#475569;line-height:1.7;">
      If he had that clause, using those files without paying would be copyright infringement. Most clients don't want that fight.
    </p>
    <table cellpadding="0" cellspacing="0" style="margin:0 auto 28px;">
      <tr><td style="background:#1e40af;border-radius:10px;">
        <a href="${STRIPE_LINK}" style="display:block;padding:16px 32px;color:#fff;font-size:16px;font-weight:700;text-decoration:none;">
          Get a Contract That Protects You &#8594;
        </a>
      </td></tr>
    </table>
    <p style="margin:0 0 4px;font-size:15px;color:#475569;">Tomorrow: the 5 contract clauses that stop 90% of freelancer disputes.</p>
    <p style="margin:0;font-size:15px;color:#475569;">&#8212; Matteo, ContractShield</p>
  </td></tr>
  <tr><td style="background:#f8fafc;padding:20px 40px;border-top:1px solid #e2e8f0;text-align:center;">
    <p style="margin:0;font-size:12px;color:#94a3b8;">
      You subscribed at <a href="${SITE_URL}" style="color:#6366f1;">contractshield.co</a> &bull; &#169; 2026 ContractShield
    </p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

// ── Email 3 — 5 Clauses ────────────────────────────────────────────────────

function email3HTML() {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>5 Clauses That Stop 90% of Disputes</title></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:'Inter',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;padding:40px 20px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.07);">
  <tr><td style="background:linear-gradient(135deg,#1e40af,#3b82f6);padding:28px 40px;text-align:center;">
    <div style="color:#fff;font-size:18px;font-weight:800;">ContractShield</div>
    <div style="color:rgba(255,255,255,0.7);font-size:12px;">contractshield.co</div>
  </td></tr>
  <tr><td style="padding:40px;">
    <p style="margin:0 0 20px;font-size:22px;font-weight:800;color:#1e293b;line-height:1.3;">5 Clauses That Stop 90% of Freelancer Disputes</p>
    <p style="margin:0 0 24px;font-size:16px;color:#475569;line-height:1.7;">After reviewing 200+ freelancer disputes, here are the 5 contract clauses that come up in almost every case:</p>

    <div style="margin-bottom:20px;">
      <div style="display:flex;align-items:flex-start;margin-bottom:12px;">
        <div style="background:#1e40af;color:#fff;border-radius:50%;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;margin-right:12px;line-height:28px;text-align:center;">1</div>
        <div>
          <p style="margin:0 0 4px;font-size:15px;font-weight:700;color:#1e293b;">IP Transfer on Payment</p>
          <p style="margin:0;font-size:14px;color:#475569;line-height:1.6;">Work product remains yours until the final invoice is paid. This one clause prevents 60% of ghosting cases.</p>
        </div>
      </div>
      <div style="display:flex;align-items:flex-start;margin-bottom:12px;">
        <div style="background:#1e40af;color:#fff;border-radius:50%;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;margin-right:12px;line-height:28px;text-align:center;">2</div>
        <div>
          <p style="margin:0 0 4px;font-size:15px;font-weight:700;color:#1e293b;">Kill Fee (30%)</p>
          <p style="margin:0;font-size:14px;color:#475569;line-height:1.6;">If the project is cancelled, you keep 30% of the remaining balance. Clients think twice before pulling the plug.</p>
        </div>
      </div>
      <div style="display:flex;align-items:flex-start;margin-bottom:12px;">
        <div style="background:#1e40af;color:#fff;border-radius:50%;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;margin-right:12px;line-height:28px;text-align:center;">3</div>
        <div>
          <p style="margin:0 0 4px;font-size:15px;font-weight:700;color:#1e293b;">Revision Cap</p>
          <p style="margin:0;font-size:14px;color:#475569;line-height:1.6;">2 rounds of revisions included. Each additional round billed at your hourly rate. End "unlimited changes" forever.</p>
        </div>
      </div>
      <div style="display:flex;align-items:flex-start;margin-bottom:12px;">
        <div style="background:#1e40af;color:#fff;border-radius:50%;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;margin-right:12px;line-height:28px;text-align:center;">4</div>
        <div>
          <p style="margin:0 0 4px;font-size:15px;font-weight:700;color:#1e293b;">Scope Creep Protection</p>
          <p style="margin:0;font-size:14px;color:#475569;line-height:1.6;">Any requests outside the agreed scope require a written change order and updated payment. Stops "while you're at it..." requests.</p>
        </div>
      </div>
      <div style="display:flex;align-items:flex-start;margin-bottom:24px;">
        <div style="background:#1e40af;color:#fff;border-radius:50%;width:28px;height:28px;display:inline-flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;flex-shrink:0;margin-right:12px;line-height:28px;text-align:center;">5</div>
        <div>
          <p style="margin:0 0 4px;font-size:15px;font-weight:700;color:#1e293b;">Late Payment Interest</p>
          <p style="margin:0;font-size:14px;color:#475569;line-height:1.6;">1.5% monthly interest on overdue invoices. Net-60 clients suddenly remember to pay on time.</p>
        </div>
      </div>
    </div>

    <div style="background:#f0fdf4;border:2px solid #22c55e;border-radius:12px;padding:24px;margin-bottom:28px;text-align:center;">
      <p style="margin:0 0 8px;font-size:16px;font-weight:800;color:#15803d;">All 5 clauses are built into every ContractShield template.</p>
      <p style="margin:0 0 16px;font-size:14px;color:#166534;">Fill in your details, download your PDF, and you're protected in under 5 minutes.</p>
      <table cellpadding="0" cellspacing="0" style="margin:0 auto;">
        <tr><td style="background:#16a34a;border-radius:10px;">
          <a href="${STRIPE_LINK}" style="display:block;padding:14px 32px;color:#fff;font-size:16px;font-weight:700;text-decoration:none;">
            Get Your Contract — $9 &#8594;
          </a>
        </td></tr>
      </table>
    </div>

    <p style="margin:0;font-size:14px;color:#94a3b8;">&#8212; Matteo, ContractShield &bull; <a href="${SITE_URL}" style="color:#6366f1;">contractshield.co</a></p>
  </td></tr>
  <tr><td style="background:#f8fafc;padding:20px 40px;border-top:1px solid #e2e8f0;text-align:center;">
    <p style="margin:0;font-size:12px;color:#94a3b8;">&#169; 2026 ContractShield</p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;
}

// ── Main handler ───────────────────────────────────────────────────────────

export default async function handler(req, res) {
  // Auth check: Vercel sends CRON_SECRET in Authorization header
  const authHeader = req.headers["authorization"] || "";
  if (CRON_SECRET && authHeader !== `Bearer ${CRON_SECRET}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
    return res.status(500).json({ error: "AWS credentials not configured" });
  }

  let items;
  try {
    items = await dynamoScan();
  } catch (err) {
    console.error("DynamoDB scan error:", err);
    return res.status(500).json({ error: "DB error" });
  }

  const now = Date.now();
  const DAY_MS = 24 * 60 * 60 * 1000;

  const results = { email2: { sent: 0, errors: 0 }, email3: { sent: 0, errors: 0 }, skipped: 0 };

  for (const item of items) {
    const email = item.email?.S;
    const subscribedAt = Number(item.subscribed_at?.N || 0);
    const email2Sent = item.email2_sent?.BOOL || false;
    const email3Sent = item.email3_sent?.BOOL || false;
    const unsubscribed = item.unsubscribed?.BOOL || false;

    if (!email || unsubscribed) { results.skipped++; continue; }

    const daysSince = (now - subscribedAt) / DAY_MS;

    // Email 2: between day 1.8 and day 2.2
    if (!email2Sent && daysSince >= 1.8 && daysSince <= 2.2) {
      try {
        await sendEmail({
          to: email,
          subject: "The $2,800 ghost client (what went wrong)",
          html: email2HTML(),
          text: "Yesterday Marcus spent 3 weeks building a site. The client disappeared with his work and $2,800. One clause would have stopped it. Read the full story: " + SITE_URL,
        });
        await dynamoUpdate(email, "email2_sent");
        results.email2.sent++;
        console.log(`Email 2 sent to ${email}`);
      } catch (err) {
        console.error(`Email 2 error for ${email}:`, err.message);
        results.email2.errors++;
      }
    }
    // Email 3: between day 3.8 and day 4.2
    else if (!email3Sent && daysSince >= 3.8 && daysSince <= 4.2) {
      try {
        await sendEmail({
          to: email,
          subject: "5 contract clauses that stop 90% of freelancer disputes",
          html: email3HTML(),
          text: "The 5 contract clauses every freelancer needs: 1. IP transfer on payment, 2. Kill fee (30%), 3. Revision cap, 4. Scope creep protection, 5. Late payment interest. All built into every ContractShield template. Get yours: " + STRIPE_LINK,
        });
        await dynamoUpdate(email, "email3_sent");
        results.email3.sent++;
        console.log(`Email 3 sent to ${email}`);
      } catch (err) {
        console.error(`Email 3 error for ${email}:`, err.message);
        results.email3.errors++;
      }
    } else {
      results.skipped++;
    }
  }

  return res.status(200).json({
    success: true,
    processed: items.length,
    results,
  });
}
