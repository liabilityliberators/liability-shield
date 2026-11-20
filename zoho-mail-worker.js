/**
 * Liability Liberators · Secure Zoho Mail invoice sender
 * Deploy as a Cloudflare Worker. Do not put Zoho client secrets or refresh
 * tokens in the HTML document. Bind a Cloudflare KV namespace named ZOHO_KV.
 */
const FROM_ADDRESS = "support@liabilityliberators.com";
const MAX_PDF_BYTES = 10 * 1024 * 1024;

function responseJson(data, status, corsHeaders) {
  const headers = new Headers(corsHeaders || {});
  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(data), { status, headers });
}

function corsFor(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allow = (env.APP_ORIGINS || "https://liabilityliberators.com,https://www.liabilityliberators.com,null")
    .split(",").map((x) => x.trim()).filter(Boolean);
  const headers = new Headers({
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Authorization,Content-Type",
    "Access-Control-Max-Age": "86400"
  });
  if (origin && allow.includes(origin)) headers.set("Access-Control-Allow-Origin", origin);
  return { headers, allowed: !origin || allow.includes(origin) };
}

function secureEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function requireConfig(env) {
  const required = ["APP_ACCESS_KEY", "ZOHO_CLIENT_ID", "ZOHO_CLIENT_SECRET", "PUBLIC_WORKER_URL"];
  const missing = required.filter((key) => !env[key]);
  if (!env.ZOHO_KV) missing.push("ZOHO_KV KV binding");
  if (missing.length) throw new Error("Worker setup incomplete: " + missing.join(", "));
}

function appAuthorized(request, env) {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return !!match && secureEqual(match[1], env.APP_ACCESS_KEY || "");
}

function accountsBase(env) {
  return (env.ZOHO_ACCOUNTS_BASE || "https://accounts.zoho.com").replace(/\/$/, "");
}
function mailBase(env) {
  return (env.ZOHO_MAIL_API_BASE || "https://mail.zoho.com").replace(/\/$/, "");
}
function callbackUrl(env) {
  return env.PUBLIC_WORKER_URL.replace(/\/$/, "") + "/zoho/callback";
}

async function refreshZohoAccessToken(env) {
  const refreshToken = await env.ZOHO_KV.get("zoho_refresh_token");
  if (!refreshToken) throw new Error("Zoho is not connected. Click Connect Zoho account in the studio first.");
  const body = new URLSearchParams({
    refresh_token: refreshToken,
    client_id: env.ZOHO_CLIENT_ID,
    client_secret: env.ZOHO_CLIENT_SECRET,
    grant_type: "refresh_token"
  });
  const res = await fetch(accountsBase(env) + "/oauth/v2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok || !payload.access_token) {
    throw new Error("Zoho could not refresh its authorization. Reconnect Zoho from the studio.");
  }
  return payload.access_token;
}

function flattenAccountEmails(account) {
  const result = [];
  if (account.primaryEmailAddress) result.push(account.primaryEmailAddress);
  if (account.mailboxAddress) result.push(account.mailboxAddress);
  if (Array.isArray(account.emailAddress)) {
    for (const item of account.emailAddress) if (item && item.mailId) result.push(item.mailId);
  }
  if (Array.isArray(account.sendMailDetails)) {
    for (const item of account.sendMailDetails) if (item && item.fromAddress && item.status !== false) result.push(item.fromAddress);
  }
  return [...new Set(result.map((x) => String(x).toLowerCase()))];
}

async function resolveSenderAccount(env, accessToken) {
  const cached = await env.ZOHO_KV.get("zoho_account_id");
  if (cached) return cached;
  const res = await fetch(mailBase(env) + "/api/accounts", {
    headers: { "Authorization": "Zoho-oauthtoken " + accessToken, "Accept": "application/json" }
  });
  const payload = await res.json().catch(() => ({}));
  if (!res.ok || !payload.data || !Array.isArray(payload.data)) {
    throw new Error("Zoho could not list the authorized Mail accounts. Check that ZohoMail.accounts.READ permission was granted.");
  }
  const account = payload.data.find((item) => item && item.accountId && flattenAccountEmails(item).includes(FROM_ADDRESS));
  if (!account) {
    throw new Error("The authorized Zoho account does not expose support@liabilityliberators.com as a sender. Authorize the mailbox that owns that address.");
  }
  await env.ZOHO_KV.put("zoho_account_id", String(account.accountId));
  return String(account.accountId);
}

async function handleConnect(request, env, corsHeaders) {
  requireConfig(env);
  const stateBytes = new Uint8Array(24);
  crypto.getRandomValues(stateBytes);
  const state = [...stateBytes].map((v) => v.toString(16).padStart(2, "0")).join("");
  await env.ZOHO_KV.put("oauth_state:" + state, "1", { expirationTtl: 600 });

  const authUrl = new URL(accountsBase(env) + "/oauth/v2/auth");
  authUrl.searchParams.set("client_id", env.ZOHO_CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", callbackUrl(env));
  authUrl.searchParams.set("scope", "ZohoMail.accounts.READ,ZohoMail.messages.CREATE");
  authUrl.searchParams.set("access_type", "offline");
  authUrl.searchParams.set("prompt", "consent");
  authUrl.searchParams.set("state", state);
  return responseJson({ ok: true, authorizationUrl: authUrl.toString() }, 200, corsHeaders);
}

function oauthResultPage(title, message, success = false) {
  const safeTitle = String(title).replace(/[&<>"']/g, "");
  const safeMessage = String(message).replace(/[&<>"']/g, "");
  const color = success ? "#2e7d4f" : "#9b3d3d";
  return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safeTitle}</title><body style="margin:0;background:#f4f2ec;font:16px/1.6 Arial,sans-serif;color:#171b21;display:grid;min-height:100vh;place-items:center"><main style="max-width:560px;margin:24px;background:white;padding:32px;border:1px solid #e3ded4;border-radius:12px"><div style="font:italic 22px Georgia;color:#b98a2e">Liability Liberators</div><h1 style="font:normal 26px Georgia;margin:18px 0 8px">${safeTitle}</h1><p>${safeMessage}</p><p style="margin-top:24px;color:${color};font-weight:bold">${success ? "Authorization complete" : "Action required"}</p><p style="font-size:13px;color:#6b7280">You can close this tab and return to the Document Studio.</p></main></body></html>`, {
    status: success ? 200 : 400,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }
  });
}

async function handleZohoCallback(request, env) {
  requireConfig(env);
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const oauthError = url.searchParams.get("error");
  if (oauthError) return oauthResultPage("Zoho authorization was declined", "You did not approve the requested Mail access. Return to the studio and connect again.");
  if (!code || !state) return oauthResultPage("Missing authorization details", "Zoho did not return the required authorization code and state values.");
  const stateKey = "oauth_state:" + state;
  const validState = await env.ZOHO_KV.get(stateKey);
  if (!validState) return oauthResultPage("Authorization expired", "The authorization link expired or has already been used. Return to the studio and connect again.");
  await env.ZOHO_KV.delete(stateKey);

  const tokenParams = new URLSearchParams({
    code,
    grant_type: "authorization_code",
    client_id: env.ZOHO_CLIENT_ID,
    client_secret: env.ZOHO_CLIENT_SECRET,
    redirect_uri: callbackUrl(env)
  });
  const tokenRes = await fetch(accountsBase(env) + "/oauth/v2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: tokenParams
  });
  const tokenData = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || !tokenData.access_token || !tokenData.refresh_token) {
    return oauthResultPage("Could not complete Zoho authorization", "Zoho did not return a refresh token. Check the OAuth application and offline access permission, then try again.");
  }

  const accountsRes = await fetch(mailBase(env) + "/api/accounts", {
    headers: { "Authorization": "Zoho-oauthtoken " + tokenData.access_token, "Accept": "application/json" }
  });
  const accountsData = await accountsRes.json().catch(() => ({}));
  if (!accountsRes.ok || !Array.isArray(accountsData.data)) {
    return oauthResultPage("Could not verify the mailbox", "Zoho authorization succeeded, but the connector could not list your Mail accounts. Verify the Zoho Mail API region and granted permissions.");
  }
  const account = accountsData.data.find((item) => item && item.accountId && flattenAccountEmails(item).includes(FROM_ADDRESS));
  if (!account) {
    return oauthResultPage("Sender mailbox not found", "This Zoho login does not expose support@liabilityliberators.com. Sign in with the Zoho user that owns this mailbox, or verify that the address is configured as a confirmed sender alias.");
  }

  await env.ZOHO_KV.put("zoho_refresh_token", tokenData.refresh_token);
  await env.ZOHO_KV.put("zoho_account_id", String(account.accountId));
  return oauthResultPage("Zoho Mail connected", "The connector verified support@liabilityliberators.com and securely stored the refresh token. You can now return to the Document Studio and test the connection.", true);
}

async function handleHealth(env, corsHeaders) {
  try {
    requireConfig(env);
    const accessToken = await refreshZohoAccessToken(env);
    const accountId = await resolveSenderAccount(env, accessToken);
    return responseJson({ ok: true, connected: true, sender: FROM_ADDRESS, accountId }, 200, corsHeaders);
  } catch (error) {
    return responseJson({ ok: false, connected: false, error: error.message || "Zoho connection test failed." }, 400, corsHeaders);
  }
}

async function zohoJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  const apiCode = payload && payload.status && Number(payload.status.code);
  if (!response.ok || (apiCode && apiCode !== 200)) {
    const detail = payload && payload.data && payload.data.moreInfo;
    throw new Error(detail || (payload.status && payload.status.description) || `Zoho Mail API returned HTTP ${response.status}`);
  }
  return payload;
}

async function handleSendInvoice(request, env, corsHeaders) {
  try {
    requireConfig(env);
    const form = await request.formData();
    const to = String(form.get("to") || "").trim();
    const cc = String(form.get("cc") || "").trim();
    const subject = String(form.get("subject") || "").trim().slice(0, 180);
    const content = String(form.get("content") || "").trim().slice(0, 40000);
    const pdf = form.get("pdf");
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(to)) throw new Error("Enter a valid recipient email address.");
    if (cc && !emailRegex.test(cc)) throw new Error("The CC email address is not valid.");
    if (!subject || !content) throw new Error("The email subject or message is missing.");
    if (!pdf || typeof pdf.arrayBuffer !== "function" || pdf.type !== "application/pdf") throw new Error("The invoice PDF attachment is missing or is not a PDF.");
    if (pdf.size < 1000 || pdf.size > MAX_PDF_BYTES) throw new Error("The PDF must be larger than 1 KB and no larger than 10 MB.");

    const accessToken = await refreshZohoAccessToken(env);
    const accountId = await resolveSenderAccount(env, accessToken);
    const fileName = String(pdf.name || "Liability-Liberators-Invoice.pdf").replace(/[^a-zA-Z0-9._-]/g, "-").slice(0, 120);
    const uploadUrl = new URL(`${mailBase(env)}/api/accounts/${accountId}/messages/attachments`);
    uploadUrl.searchParams.set("fileName", fileName);
    uploadUrl.searchParams.set("isInline", "false");
    const upload = await zohoJson(uploadUrl.toString(), {
      method: "POST",
      headers: {
        "Authorization": "Zoho-oauthtoken " + accessToken,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: await pdf.arrayBuffer()
    });
    const attachment = upload.data;
    if (!attachment || !attachment.storeName || !attachment.attachmentPath || !attachment.attachmentName) {
      throw new Error("Zoho accepted the upload but did not return the attachment details needed to send the email.");
    }

    const mailPayload = {
      fromAddress: FROM_ADDRESS,
      toAddress: to,
      subject,
      content,
      mailFormat: "plaintext",
      attachments: [{
        storeName: attachment.storeName,
        attachmentPath: attachment.attachmentPath,
        attachmentName: attachment.attachmentName
      }]
    };
    if (cc) mailPayload.ccAddress = cc;
    const sent = await zohoJson(`${mailBase(env)}/api/accounts/${accountId}/messages`, {
      method: "POST",
      headers: {
        "Authorization": "Zoho-oauthtoken " + accessToken,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(mailPayload)
    });
    return responseJson({
      ok: true,
      sent: true,
      sender: FROM_ADDRESS,
      to,
      messageId: sent.data && sent.data.messageId ? String(sent.data.messageId) : null
    }, 200, corsHeaders);
  } catch (error) {
    return responseJson({ ok: false, sent: false, error: error.message || "The invoice could not be sent through Zoho." }, 400, corsHeaders);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { headers: corsHeaders, allowed } = corsFor(request, env);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    if (!allowed) return responseJson({ ok: false, error: "This website origin is not allowed to use the mail connector." }, 403, corsHeaders);

    if (url.pathname === "/zoho/callback" && request.method === "GET") {
      try { return await handleZohoCallback(request, env); }
      catch (error) { return oauthResultPage("Zoho setup error", error.message || "The authorization callback failed."); }
    }

    if (!appAuthorized(request, env)) return responseJson({ ok: false, error: "Unauthorized. Check the private studio access key." }, 401, corsHeaders);

    if (url.pathname === "/zoho/connect" && request.method === "POST") {
      try { return await handleConnect(request, env, corsHeaders); }
      catch (error) { return responseJson({ ok: false, error: error.message || "Could not begin Zoho authorization." }, 400, corsHeaders); }
    }
    if (url.pathname === "/health" && request.method === "GET") return handleHealth(env, corsHeaders);
    if (url.pathname === "/send-invoice" && request.method === "POST") return handleSendInvoice(request, env, corsHeaders);
    return responseJson({ ok: false, error: "Not found." }, 404, corsHeaders);
  }
};
