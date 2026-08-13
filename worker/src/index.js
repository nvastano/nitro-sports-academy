var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://nitrosportsacademy.com",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, "Content-Type": "application/json" }
  });
}
__name(json, "json");
function err(message, status = 400) {
  return json({ error: message }, status);
}
__name(err, "err");

var MEMBERSHIP_JOIN = `
  LEFT JOIN memberships m ON (
    m.id = (
      SELECT id FROM memberships
      WHERE (client_id = c.id OR household_id = c.household_id)
      ORDER BY (status = 'active') DESC, created_at DESC LIMIT 1
    )
  )
`;
async function signJWT(payload, secret) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = btoa(JSON.stringify(payload));
  const data = `${header}.${body}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  return `${data}.${sigB64}`;
}
__name(signJWT, "signJWT");
async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const data = `${parts[0]}.${parts[1]}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const sigBytes = Uint8Array.from(
    atob(parts[2].replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0)
  );
  const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(data));
  if (!valid) return null;
  const payload = JSON.parse(atob(parts[1]));
  if (payload.exp && Date.now() / 1e3 > payload.exp) return null;
  return payload;
}
__name(verifyJWT, "verifyJWT");
async function requireAuth(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  return verifyJWT(auth.slice(7), env.JWT_SECRET);
}
__name(requireAuth, "requireAuth");
function uuid() {
  return crypto.randomUUID();
}
__name(uuid, "uuid");
async function assertAccessCodeAvailable(code, env, excludeClientId) {
  const existing = await env.DB.prepare("SELECT id FROM clients WHERE access_code = ?").bind(code).first();
  if (existing && existing.id !== excludeClientId) throw new Error("That access code is already in use by another client");
}
__name(assertAccessCodeAvailable, "assertAccessCodeAvailable");
var MEMBERSHIP_PRICES = { individual: 395, family_2: 595, family_3plus: 645 };
var MEMBERSHIP_TYPE_LABEL = { individual: "Individual", family_2: "Family (2 siblings)", family_3plus: "Family (3+ siblings)" };

function computeMembershipDue(m) {
  if (!m || !m.renewal_date || m.status !== "active") return 0;
  const price = m.custom_price ?? MEMBERSHIP_PRICES[m.type] ?? 0;
  const dueFrom = new Date(m.renewal_date);
  dueFrom.setMonth(dueFrom.getMonth() - 1);
  return new Date() >= dueFrom ? price : 0;
}
var GUEST_CAGE_PRICES = { 30: 30, 60: 50 };
function normalizePhone(p) {
  return (p ?? "").replace(/\D/g, "").replace(/^1(\d{10})$/, "$1");
}
__name(normalizePhone, "normalizePhone");

// ── Twilio SMS ────────────────────────────────────────────────────────────────
async function sendSMS(env, to, body) {
  const sid  = env.TWILIO_ACCOUNT_SID;
  const auth = env.TWILIO_AUTH_TOKEN;
  const from = env.TWILIO_PHONE_NUMBER;
  if (!sid || !auth || !from) {
    console.error("SMS skipped: missing Twilio env vars", { sid: !!sid, auth: !!auth, from: !!from });
    return;
  }
  const toNorm = normalizePhone(to);
  if (!toNorm || toNorm.length !== 10) {
    console.error("SMS skipped: invalid phone number", to, "->", toNorm);
    return;
  }
  const url = `https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": "Basic " + btoa(`${sid}:${auth}`),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ To: `+1${toNorm}`, From: from, Body: body }).toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    console.error("SMS Twilio error", res.status, text);
  } else {
    console.log("SMS sent to", toNorm);
  }
}
__name(sendSMS, "sendSMS");
// ─────────────────────────────────────────────────────────────────────────────

async function isActiveMember(email, phone, env) {
  const e = (email ?? "").trim().toLowerCase();
  const p = normalizePhone(phone);
  if (!e && !p) return false;
  let candidates = [];
  if (e) {
    const { results } = await env.DB.prepare(`SELECT c.id, c.phone, m.status FROM clients c ${MEMBERSHIP_JOIN} WHERE trim(lower(c.email)) = ?`).bind(e).all();
    candidates = results;
  }
  if (!candidates.length && p) {
    const { results } = await env.DB.prepare(`SELECT c.id, c.phone, m.status FROM clients c ${MEMBERSHIP_JOIN}`).all();
    candidates = results.filter((c) => normalizePhone(c.phone) === p);
  }
  return candidates.some((c) => c.status === "active");
}
async function getClientId(email, phone, env) {
  const e = (email ?? "").trim().toLowerCase();
  const p = normalizePhone(phone);
  if (!e && !p) return null;
  if (e) {
    const row = await env.DB.prepare(`SELECT c.id, m.status FROM clients c ${MEMBERSHIP_JOIN} WHERE trim(lower(c.email)) = ?`).bind(e).first();
    if (row?.status === "active") return row.id;
  }
  if (p) {
    const { results } = await env.DB.prepare(`SELECT c.id, c.phone, m.status FROM clients c ${MEMBERSHIP_JOIN}`).all();
    const match = results.filter((c) => normalizePhone(c.phone) === p).find((c) => c.status === "active");
    if (match) return match.id;
  }
  return null;
}
__name(isActiveMember, "isActiveMember");
async function hasSignedWaiver(email, env) {
  const e = (email ?? "").trim().toLowerCase();
  if (!e) return false;
  const row = await env.DB.prepare("SELECT id FROM waivers WHERE lower(guardian_email) = ? ORDER BY signed_at DESC LIMIT 1").bind(e).first();
  return !!row;
}
__name(hasSignedWaiver, "hasSignedWaiver");
async function upsertGuestLead(b, env) {
  const email = (b.player_email ?? "").trim().toLowerCase();
  if (!email) return;
  const existing = await env.DB.prepare("SELECT id FROM clients WHERE lower(email) = ?").bind(email).first();
  if (existing) return;
  const nameParts = b.player_name.trim().split(/\s+/);
  await env.DB.prepare(`
    INSERT INTO clients (id, first_name, last_name, email, phone, lead_status, inquiry_type)
    VALUES (?, ?, ?, ?, ?, 'lead', 'guest_cage_booking')
  `).bind(
    uuid(),
    nameParts[0] ?? b.player_name.trim(),
    nameParts.slice(1).join(" ") || "",
    email,
    b.player_phone?.trim() || null
  ).run();
}
__name(upsertGuestLead, "upsertGuestLead");
function squareBase(env) {
  return env.SQUARE_ENV === "production" ? "https://connect.squareup.com" : "https://connect.squareupsandbox.com";
}
__name(squareBase, "squareBase");
async function createSquarePaymentLink(bookingId, booking, price, duration, env) {
  const cageLabel = CAGE_LABEL[booking.cage] ?? booking.cage;
  const res = await fetch(`${squareBase(env)}/v2/online-checkout/payment-links`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.SQUARE_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
      "Square-Version": "2024-01-18"
    },
    body: JSON.stringify({
      idempotency_key: uuid(),
      quick_pay: {
        name: `${cageLabel} — ${duration} min (${booking.date} ${booking.time})`,
        price_money: { amount: Math.round(price * 100), currency: "USD" },
        location_id: env.SQUARE_LOCATION_ID
      },
      checkout_options: {
        redirect_url: `https://nitrosportsacademy.com/schedule.html?payment=success&booking=${bookingId}`
      },
      pre_populated_data: booking.player_email ? { buyer_email: booking.player_email } : void 0
    })
  });
  if (!res.ok) throw new Error(`Square payment link error ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return { url: data.payment_link.url, orderId: data.payment_link.order_id };
}
__name(createSquarePaymentLink, "createSquarePaymentLink");
async function createMembershipPaymentLink(membershipId, planLabel, price, email, env) {
  const res = await fetch(`${squareBase(env)}/v2/online-checkout/payment-links`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${env.SQUARE_ACCESS_TOKEN}`,
      "Content-Type": "application/json",
      "Square-Version": "2024-01-18"
    },
    body: JSON.stringify({
      idempotency_key: uuid(),
      quick_pay: {
        name: `Nitro Sports Academy Membership — ${planLabel}`,
        price_money: { amount: Math.round(price * 100), currency: "USD" },
        location_id: env.SQUARE_LOCATION_ID
      },
      checkout_options: {
        redirect_url: `https://nitrosportsacademy.com/membership-signup.html?payment=success&membership=${membershipId}`
      },
      pre_populated_data: email ? { buyer_email: email } : void 0
    })
  });
  if (!res.ok) throw new Error(`Square payment link error ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return { url: data.payment_link.url, orderId: data.payment_link.order_id };
}
__name(createMembershipPaymentLink, "createMembershipPaymentLink");
async function sendMembershipActiveNotification(client, membership, env) {
  const typeLabel = MEMBERSHIP_TYPE_LABEL[membership.type] ?? membership.type;
  const adminHtml = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0D1321;font-family:Arial,sans-serif;color:#C8CDD9">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
  <div style="font-family:Arial,sans-serif;font-size:1.1rem;font-weight:700;text-transform:uppercase;color:#fff;margin-bottom:24px"><span style="color:#3d65cc">NITRO</span> SPORTS ACADEMY</div>
  <div style="background:#1C2540;border-radius:8px;padding:28px;margin-bottom:20px">
    <h2 style="color:#fff;font-size:18px;margin:0 0 16px">💰 New Membership Payment Received</h2>
    <p style="color:#9AA0B4;font-size:14px;margin:0 0 16px">Send this member their facility access code.</p>
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Name</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${client.first_name} ${client.last_name}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Plan</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${typeLabel}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Email</td><td style="color:#fff;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${client.email ?? "—"}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0">Phone</td><td style="color:#fff;text-align:right;padding:8px 0">${client.phone ?? "—"}</td></tr>
    </table>
  </div>
  <p style="color:#9AA0B4;font-size:13px;text-align:center">View this member at <a href="https://nitrosportsacademy.com/admin-dashboard.html" style="color:#3d65cc">the admin dashboard</a>.</p>
</div>
</body></html>`;
  const res1 = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
      reply_to: ["coach.pedro.tn@gmail.com"],
      to: ["coach.pedro.tn@gmail.com"],
      bcc: ["nicholas.vastano@gmail.com"],
      subject: `New Membership Payment — ${client.first_name} ${client.last_name}`,
      html: adminHtml
    })
  });
  if (!res1.ok) throw new Error(`Resend error ${res1.status}: ${await res1.text()}`);
  if (client.email) {
    const memberHtml = `<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0D1321;font-family:Arial,sans-serif;color:#C8CDD9">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
  <div style="font-family:Arial,sans-serif;font-size:1.1rem;font-weight:700;text-transform:uppercase;color:#fff;margin-bottom:24px"><span style="color:#3d65cc">NITRO</span> SPORTS ACADEMY</div>
  <div style="background:#1C2540;border-radius:8px;padding:28px;margin-bottom:20px">
    <h2 style="color:#fff;font-size:20px;margin:0 0 6px">Welcome to the Nitro Family, ${client.first_name}! 🎉</h2>
    <p style="color:#9AA0B4;font-size:14px;margin:0 0 16px">Your <strong style="color:#fff">${typeLabel}</strong> membership payment has been received and your membership is officially <strong style="color:#fff">active</strong>. We're pumped to have you training with us!</p>
    <p style="color:#9AA0B4;font-size:14px;margin:0 0 16px">The owner of Nitro Sports Academy will be reaching out to you soon with your personal facility access code — this is what gets you in the door, so keep an eye on your phone and email over the next few days.</p>
    <p style="color:#9AA0B4;font-size:14px;margin:0">If you'd like a tour before your first visit, Pedro is happy to show you around the facility and walk you through the cages — just reply to this email or give him a call to set up a time.</p>
  </div>
  <p style="color:#9AA0B4;font-size:13px;text-align:center">Questions? Reply to this email or call Pedro at <a href="tel:6158708077" style="color:#3d65cc;">(615) 870-8077</a>.</p>
  <div style="text-align:center;margin-top:24px;font-size:12px;color:#6B7189">Nitro Sports Academy &middot; nitrosportsacademy.com</div>
</div>
</body></html>`;
    const res2 = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
        reply_to: ["coach.pedro.tn@gmail.com"],
        to: [client.email],
        subject: `Welcome to Nitro Sports Academy — Membership Active`,
        html: memberHtml
      })
    });
    if (!res2.ok) throw new Error(`Resend error ${res2.status}: ${await res2.text()}`);
  }
}
__name(sendMembershipActiveNotification, "sendMembershipActiveNotification");
async function verifySquareSignature(request, rawBody, env) {
  const signature = request.headers.get("x-square-hmacsha256-signature");
  if (!signature) return false;
  const notificationUrl = `https://${request.headers.get("host") ?? "nitro-crm.nicholas-vastano.workers.dev"}/webhooks/square`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.SQUARE_WEBHOOK_SIGNATURE_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(notificationUrl + rawBody));
  const expected = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return expected === signature;
}
__name(verifySquareSignature, "verifySquareSignature");
async function sendGuestPaymentPendingEmail(booking, price, paymentLinkUrl, env) {
  const cageLabel = CAGE_LABEL[booking.cage] ?? booking.cage;
  const payButton = paymentLinkUrl
    ? `<div style="text-align:center;margin:0 0 20px"><a href="${paymentLinkUrl}" target="_blank" style="display:inline-block;background:#2B4FA8;color:#fff;text-decoration:none;padding:14px 32px;border-radius:6px;font-family:Arial,sans-serif;font-size:15px;font-weight:700;">Pay $${price.toFixed(2)} Now</a></div>`
    : "";
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0D1321;font-family:Arial,sans-serif;color:#C8CDD9">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
  <div style="font-family:Arial,sans-serif;font-size:1.1rem;font-weight:700;text-transform:uppercase;color:#fff;margin-bottom:24px"><span style="color:#3d65cc">NITRO</span> SPORTS ACADEMY</div>
  <div style="background:#1C2540;border-radius:8px;padding:28px;margin-bottom:20px">
    <h2 style="color:#fff;font-size:20px;margin:0 0 6px">Almost There — Payment Required</h2>
    <p style="color:#9AA0B4;font-size:14px;margin:0 0 24px">Hi ${booking.player_name}, your spot is held below. Complete payment to confirm it.</p>
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Cage</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${cageLabel}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Date</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.date}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Time</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.time} CT</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Duration</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.duration} minutes</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0">Price</td><td style="color:#E8B84B;font-weight:700;text-align:right;padding:8px 0">$${price.toFixed(2)}</td></tr>
    </table>
  </div>
  ${payButton}
  <p style="color:#9AA0B4;font-size:13px;text-align:center">Your slot is held but not guaranteed until payment is received. Questions? Reply to this email or call Pedro at <a href="tel:6158708077" style="color:#3d65cc;">(615) 870-8077</a>.</p>
  <div style="text-align:center;margin-top:24px;font-size:12px;color:#6B7189">Nitro Sports Academy &middot; nitrosportsacademy.com</div>
</div>
</body></html>`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
      reply_to: ["coach.pedro.tn@gmail.com"],
      to: [booking.player_email],
      subject: `Payment Required — ${cageLabel} on ${booking.date} at ${booking.time}`,
      html
    })
  });
  if (!res.ok) throw new Error(`Resend error ${res.status}: ${await res.text()}`);
}
__name(sendGuestPaymentPendingEmail, "sendGuestPaymentPendingEmail");
var GCAL_CALENDARS = {
  cage_1: "53eb678c1bdbd86f297d873d2bb130aa94c2ec3a69920a97c3fa34d587bc752c@group.calendar.google.com",
  cage_2: "fef7a3537071bd19e82c757d80941a97130e42f47f8c71de5ded7496c15c62f7@group.calendar.google.com",
  cage_3: "36732814ecce1f606d188a74c37b3603ff7931260f08f6f89262cf01baa47a78@group.calendar.google.com",
  pitching_lane: "f7479cb5c3009a90d96240288139559f609e423c753188265e8cbcc8ad57dfab@group.calendar.google.com"
};
var CAGE_LABEL = { cage_1: "Cage 1", cage_2: "Cage 2", cage_3: "Cage 3", pitching_lane: "Pitching Lane" };
async function getGCalToken(env) {
  const now = Math.floor(Date.now() / 1e3);
  const b64u = /* @__PURE__ */ __name((obj) => btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, ""), "b64u");
  const toSign = `${b64u({ alg: "RS256", typ: "JWT" })}.${b64u({
    iss: env.GCAL_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/calendar",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now
  })}`;
  const pem = env.GCAL_PRIVATE_KEY.replace(/-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\n/g, "");
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(toSign));
  const jwt = `${toSign}.${btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")}`;
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`
  });
  const data = await res.json();
  if (!data.access_token) throw new Error(`GCal token: ${JSON.stringify(data)}`);
  return data.access_token;
}
__name(getGCalToken, "getGCalToken");
function slotStart(date, time) {
  const [t, ap] = time.split(" ");
  let [h, m] = t.split(":").map(Number);
  if (ap === "PM" && h !== 12) h += 12;
  if (ap === "AM" && h === 12) h = 0;
  return `${date}T${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:00`;
}
__name(slotStart, "slotStart");
function add30Min(date, startISO) {
  const h = parseInt(startISO.slice(11, 13));
  const m = parseInt(startISO.slice(14, 16));
  const endH = m === 30 ? h + 1 : h;
  const endM = m === 30 ? 0 : 30;
  return `${date}T${String(endH).padStart(2, "0")}:${String(endM).padStart(2, "0")}:00`;
}
__name(add30Min, "add30Min");
function generateICS(booking, id) {
  const cageLabel = CAGE_LABEL[booking.cage] ?? booking.cage;
  const [t, ap] = booking.time.split(" ");
  let [h, m] = t.split(":").map(Number);
  if (ap === "PM" && h !== 12) h += 12;
  if (ap === "AM" && h === 12) h = 0;
  const endH = m === 30 ? h + 1 : h;
  const endM = m === 30 ? 0 : 30;
  const dateStr = booking.date.replace(/-/g, "");
  const pad = (n) => String(n).padStart(2, "0");
  const startDT = `${dateStr}T${pad(h)}${pad(m)}00`;
  const endDT   = `${dateStr}T${pad(endH)}${pad(endM)}00`;
  const stamp   = new Date().toISOString().replace(/[-:.]/g, "").slice(0, 15) + "Z";
  return [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    "PRODID:-//Nitro Sports Academy//Schedule//EN",
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    "BEGIN:VEVENT",
    `UID:${id}@nitrosportsacademy.com`,
    `DTSTAMP:${stamp}`,
    `DTSTART;TZID=America/Chicago:${startDT}`,
    `DTEND;TZID=America/Chicago:${endDT}`,
    `SUMMARY:${cageLabel} - Nitro Sports Academy`,
    `DESCRIPTION:Your 30-min cage booking is confirmed!\\nPlayer: ${booking.player_name}\\nLocation: 3710 John Lunn Rd\\, Ste 2\\, Spring Hill\\, TN 37174\\nQuestions? Call Pedro at (615) 870-8077`,
    "LOCATION:3710 John Lunn Rd\\, Ste 2\\, Spring Hill\\, TN 37174",
    "END:VEVENT",
    "END:VCALENDAR"
  ].join("\r\n");
}
__name(generateICS, "generateICS");
async function createCalendarEvent(token, calId, booking) {
  const start = slotStart(booking.date, booking.time);
  const h = parseInt(start.slice(11, 13));
  const end = `${booking.date}T${String(h + 1).padStart(2, "0")}:${start.slice(14, 16)}:00`;
  const disc = { hitting: "⚾ Hitting", pitching: "\u{1F3AF} Pitching", catching: "\u{1F9E4} Catching" }[booking.discipline];
  const res = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      summary: `${disc} — ${booking.player_name}`,
      description: [
        `Shared Session | ${CAGE_LABEL[booking.cage_assigned]}`,
        `Player: ${booking.player_name}`,
        `Email: ${booking.player_email ?? "—"}`,
        `Phone: ${booking.player_phone ?? "—"}`,
        booking.player_age ? `Age: ${booking.player_age}` : null,
        `Booked via nitrosportsacademy.com`
      ].filter(Boolean).join("\n"),
      start: { dateTime: start, timeZone: "America/Chicago" },
      end: { dateTime: end, timeZone: "America/Chicago" },
      colorId: booking.discipline === "hitting" ? "9" : booking.discipline === "pitching" ? "5" : "2"
    })
  });
  if (!res.ok) throw new Error(`GCal create: ${await res.text()}`);
  return await res.json();
}
__name(createCalendarEvent, "createCalendarEvent");
async function deleteCalendarEvent(token, calId, eventId) {
  const res = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events/${eventId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!res.ok && res.status !== 404 && res.status !== 410) throw new Error(`GCal delete: ${res.status}`);
}
__name(deleteCalendarEvent, "deleteCalendarEvent");
async function pickCage(db, date, time, discipline) {
  return discipline === "pitching" ? "pitching_lane" : "cage_2";
}
__name(pickCage, "pickCage");
async function createScheduleCalendarEvent(token, calId, booking) {
  const start = slotStart(booking.date, booking.time);
  const end = add30Min(booking.date, start);
  const res = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      summary: `${booking.player_name} — ${CAGE_LABEL[booking.cage_assigned] ?? booking.cage_assigned}`,
      description: [
        `Cage Booking (30 min) | ${CAGE_LABEL[booking.cage_assigned] ?? booking.cage_assigned}`,
        `Player: ${booking.player_name}`,
        `Email: ${booking.player_email ?? "—"}`,
        `Phone: ${booking.player_phone ?? "—"}`,
        `Booked via nitrosportsacademy.com/schedule.html`
      ].join("\n"),
      start: { dateTime: start, timeZone: "America/Chicago" },
      end: { dateTime: end, timeZone: "America/Chicago" }
    })
  });
  if (!res.ok) throw new Error(`GCal create: ${await res.text()}`);
  return await res.json();
}
__name(createScheduleCalendarEvent, "createScheduleCalendarEvent");
async function sendBookingRequestNotification(booking, env, autoConfirmed = false) {
  const cageLabel = CAGE_LABEL[booking.cage] ?? booking.cage;
  const statusLabel = autoConfirmed ? "Auto-Confirmed Booking" : "New Cage Booking Request";
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0D1321;font-family:Arial,sans-serif;color:#C8CDD9">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
  <div style="font-family:Arial,sans-serif;font-size:1.1rem;font-weight:700;text-transform:uppercase;color:#fff;margin-bottom:24px"><span style="color:#3d65cc">NITRO</span> SPORTS ACADEMY</div>
  <div style="background:#1C2540;border-radius:8px;padding:28px;margin-bottom:20px">
    <h2 style="color:#fff;font-size:18px;margin:0 0 16px">${statusLabel}</h2>
    ${autoConfirmed ? '<p style="color:#4ade80;font-size:13px;margin:0 0 16px;">✅ This booking was auto-confirmed and added to Google Calendar.</p>' : ''}
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Cage</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${cageLabel}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Date</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.date}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Time</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.time} (30 min)</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Player</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.player_name}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Email</td><td style="color:#fff;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.player_email ?? "—"}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Phone</td><td style="color:#fff;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.player_phone ?? "—"}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0">SMS Confirmation</td><td style="text-align:right;padding:8px 0;font-weight:600;color:${booking.sms_consent ? '#4ade80' : '#9AA0B4'}">${booking.sms_consent ? '✅ Opted in' : 'No'}</td></tr>
    </table>
  </div>
  <p style="color:#9AA0B4;font-size:13px;text-align:center">View bookings at <a href="https://nitrosportsacademy.com/admin-dashboard.html" style="color:#3d65cc">the admin dashboard</a>.</p>
</div>
</body></html>`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
      reply_to: ["coach.pedro.tn@gmail.com"],
      to: ["coach.pedro.tn@gmail.com"],
      bcc: ["nicholas.vastano@gmail.com"],
      subject: `${autoConfirmed ? "Auto-Confirmed" : "New Booking Request"} — ${cageLabel} on ${booking.date} at ${booking.time}`,
      html
    })
  });
  if (!res.ok) throw new Error(`Resend error ${res.status}: ${await res.text()}`);
}
__name(sendBookingRequestNotification, "sendBookingRequestNotification");
async function sendAutoConfirmedEmail(booking, id, env) {
  const cageLabel = CAGE_LABEL[booking.cage] ?? booking.cage;
  const [t, ap] = booking.time.split(" ");
  let [h, m] = t.split(":").map(Number);
  if (ap === "PM" && h !== 12) h += 12;
  if (ap === "AM" && h === 12) h = 0;
  const pad = (n) => String(n).padStart(2, "0");
  const endH = m === 30 ? h + 1 : h;
  const endM = m === 30 ? 0 : 30;
  const dateNoHyphens = booking.date.replace(/-/g, "");
  const gcalStart = `${dateNoHyphens}T${pad(h)}${pad(m)}00`;
  const gcalEnd   = `${dateNoHyphens}T${pad(endH)}${pad(endM)}00`;
  const gcalLink  = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(cageLabel + ' - Nitro Sports Academy')}&dates=${gcalStart}/${gcalEnd}&ctz=America%2FChicago&details=${encodeURIComponent('30-min cage booking at Nitro Sports Academy\n3710 John Lunn Rd, Ste 2, Spring Hill, TN 37174\nQuestions? Call Pedro at (615) 870-8077')}&location=${encodeURIComponent('3710 John Lunn Rd, Ste 2, Spring Hill, TN 37174')}`;

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0D1321;font-family:Arial,sans-serif;color:#C8CDD9">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
  <div style="font-family:Arial,sans-serif;font-size:1.1rem;font-weight:700;text-transform:uppercase;color:#fff;margin-bottom:24px"><span style="color:#3d65cc">NITRO</span> SPORTS ACADEMY</div>
  <div style="background:#1C2540;border-radius:8px;padding:28px;margin-bottom:20px">
    <h2 style="color:#fff;font-size:20px;margin:0 0 6px">You're Booked! ✅</h2>
    <p style="color:#9AA0B4;font-size:14px;margin:0 0 24px">Hi ${booking.player_name}, your 30-min slot is confirmed. See you out there!</p>
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Cage</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${cageLabel}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Date</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.date}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Time</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.time} CT</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0">Duration</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0">30 minutes</td></tr>
    </table>
  </div>
  <div style="background:#1C2540;border-radius:8px;padding:24px;margin-bottom:20px;text-align:center">
    <p style="color:#9AA0B4;font-size:13px;margin:0 0 16px;">Save this event to your calendar. A .ics file is attached, or use the button below:</p>
    <a href="${gcalLink}" target="_blank" style="display:inline-block;background:#2B4FA8;color:#fff;text-decoration:none;padding:12px 28px;border-radius:5px;font-family:Arial,sans-serif;font-size:14px;font-weight:700;">Add to Google Calendar</a>
  </div>
  <div style="background:#1C2540;border-radius:8px;padding:24px;margin-bottom:20px;text-align:center;border:1px solid rgba(232,184,75,0.4)">
    <p style="color:#9AA0B4;font-size:13px;margin:0 0 8px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;">Building Access Code</p>
    <p style="color:#E8B84B;font-size:28px;font-weight:700;margin:0 0 8px;letter-spacing:0.05em;">${env.GUEST_ACCESS_CODE}</p>
    <p style="color:#9AA0B4;font-size:13px;margin:0;">Enter this code at the door to get into the building for your reserved time.</p>
  </div>
  <div style="background:#1C2540;border-radius:8px;padding:20px;margin-bottom:20px">
    <p style="color:#9AA0B4;font-size:13px;margin:0 0 8px;font-weight:700;text-transform:uppercase;letter-spacing:0.05em;">Location</p>
    <p style="color:#fff;font-size:14px;margin:0;">3710 John Lunn Rd, Ste 2<br>Spring Hill, TN 37174</p>
  </div>
  <p style="color:#9AA0B4;font-size:13px;text-align:center">Questions? Reply to this email or call Pedro at <a href="tel:6158708077" style="color:#3d65cc;">(615) 870-8077</a>.</p>
  <div style="text-align:center;margin-top:24px;font-size:12px;color:#6B7189">Nitro Sports Academy &middot; nitrosportsacademy.com</div>
</div>
</body></html>`;

  const icsContent = generateICS(booking, id);
  const icsBase64 = btoa(unescape(encodeURIComponent(icsContent)));

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
      reply_to: ["coach.pedro.tn@gmail.com"],
      to: [booking.player_email],
      subject: `Booking Confirmed — ${cageLabel} on ${booking.date} at ${booking.time}`,
      html,
      attachments: [{ filename: "nitro-booking.ics", content: icsBase64 }]
    })
  });
  if (!res.ok) throw new Error(`Resend error ${res.status}: ${await res.text()}`);
}
__name(sendAutoConfirmedEmail, "sendAutoConfirmedEmail");
async function sendCancellationEmail(booking, env) {
  if (!booking.player_email) return;
  const cageLabel = CAGE_LABEL[booking.cage_assigned] ?? booking.cage_assigned ?? "your session";
  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0D1321;font-family:Arial,sans-serif;color:#C8CDD9">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
  <div style="font-family:Arial,sans-serif;font-size:1.1rem;font-weight:700;text-transform:uppercase;color:#fff;margin-bottom:24px"><span style="color:#3d65cc">NITRO</span> SPORTS ACADEMY</div>
  <div style="background:#1C2540;border-radius:8px;padding:28px;margin-bottom:20px">
    <h2 style="color:#fff;font-size:20px;margin:0 0 6px">Booking Cancelled</h2>
    <p style="color:#9AA0B4;font-size:14px;margin:0 0 24px">Hi ${booking.player_name}, your booking below has been cancelled.</p>
    <table style="width:100%;border-collapse:collapse">
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Cage</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${cageLabel}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0;border-bottom:1px solid #2B3558">Date</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0;border-bottom:1px solid #2B3558">${booking.date}</td></tr>
      <tr><td style="color:#9AA0B4;padding:8px 0">Time</td><td style="color:#fff;font-weight:600;text-align:right;padding:8px 0">${booking.time} CT</td></tr>
    </table>
  </div>
  <p style="color:#9AA0B4;font-size:13px;text-align:center">If you'd like to rebook, head back to <a href="https://nitrosportsacademy.com/schedule.html" style="color:#3d65cc">the schedule page</a>. Questions? Reply to this email or call Pedro at <a href="tel:6158708077" style="color:#3d65cc;">(615) 870-8077</a>.</p>
  <div style="text-align:center;margin-top:24px;font-size:12px;color:#6B7189">Nitro Sports Academy &middot; nitrosportsacademy.com</div>
</div>
</body></html>`;
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
      reply_to: ["coach.pedro.tn@gmail.com"],
      to: [booking.player_email],
      subject: `Booking Cancelled — ${cageLabel} on ${booking.date} at ${booking.time}`,
      html
    })
  });
  if (!res.ok) throw new Error(`Resend error ${res.status}: ${await res.text()}`);
}
__name(sendCancellationEmail, "sendCancellationEmail");
var src_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;
    if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS_HEADERS });
    if (method === "POST" && path === "/auth/login") {
      const { username, password } = await request.json();
      if (username !== env.ADMIN_USERNAME || password !== env.ADMIN_PASSWORD)
        return err("Invalid credentials", 401);
      const token = await signJWT(
        { sub: username, exp: Math.floor(Date.now() / 1e3) + 60 * 60 * 24 * 7 },
        env.JWT_SECRET
      );
      return json({ token });
    }
    if (method === "POST" && path === "/webhooks/calendly") {
      const payload = await request.json();
      const event = payload?.event;
      const invitee = payload?.payload?.invitee;
      if (event === "invitee.created" && invitee?.email) {
        const row = await env.DB.prepare("SELECT id FROM clients WHERE email = ?").bind(invitee.email).first();
        if (row) {
          await env.DB.prepare(
            "INSERT INTO bookings (id,client_id,calendly_event_id,event_type,start_time,end_time) VALUES (?,?,?,?,?,?)"
          ).bind(
            uuid(), row.id,
            payload.payload?.event?.uri ?? null,
            payload.payload?.event_type?.name ?? null,
            payload.payload?.event?.start_time ?? null,
            payload.payload?.event?.end_time ?? null
          ).run();
        }
      }
      return json({ ok: true });
    }
    if (method === "POST" && path === "/webhooks/contact") {
      const b = await request.json();
      const email = (b.email ?? "").trim().toLowerCase();
      if (!email) return json({ ok: true });
      const existing = await env.DB.prepare("SELECT id FROM clients WHERE email = ?").bind(email).first();
      if (existing) return json({ ok: true, duplicate: true });
      const id = uuid();
      await env.DB.prepare(`
        INSERT INTO clients
          (id, first_name, last_name, email, phone, inquiry_type, inquiry_notes, lead_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'lead')
      `).bind(
        id,
        (b.first_name ?? "").trim() || "Unknown",
        (b.last_name ?? "").trim() || "",
        email,
        (b.phone ?? "").trim() || null,
        (b.interest ?? "").trim() || null,
        (b.message ?? "").trim() || null
      ).run();
      return json({ ok: true, id }, 201);
    }
    if (method === "POST" && path === "/schedule-bookings") {
      const b = await request.json();
      if (!b.player_name) return err("player_name required");
      if (!b.date || !b.time || !b.cage) return err("date, time, and cage required");
      const validCages = ["cage_1", "cage_2", "cage_3", "pitching_lane"];
      if (!validCages.includes(b.cage)) return err("invalid cage");
      const duration = [30, 60].includes(b.duration) ? b.duration : 30;
      const smsConsent = b.sms_consent ? 1 : 0;
      const { results: taken } = await env.DB.prepare(
        `SELECT id FROM bookings WHERE date=? AND time=? AND cage_assigned=? AND booking_type='cage_request' AND status IN ('pending','confirmed','pending_payment')`
      ).bind(b.date, b.time, b.cage).all();
      if (taken.length > 0) return err("This slot has already been requested", 409);

      const isMember = await isActiveMember(b.player_email, b.player_phone, env);
      const clientId = await getClientId(b.player_email, b.player_phone, env);
      const id = uuid();
      const cageLabel = CAGE_LABEL[b.cage] ?? b.cage;

      if (isMember) {
        await env.DB.prepare(
          `INSERT INTO bookings (id,client_id,date,time,discipline,player_name,player_email,player_phone,status,cage_assigned,booking_type,duration,is_member,payment_status,sms_consent)
           VALUES (?,?,?,?,'cage_request',?,?,?,'confirmed',?,'cage_request',?,1,'n/a',?)`
        ).bind(id, clientId, b.date, b.time, b.player_name.trim(), b.player_email?.trim() || null, b.player_phone?.trim() || null, b.cage, duration, smsConsent).run();
        let gcalEventId = null;
        try {
          const token = await getGCalToken(env);
          const calId = GCAL_CALENDARS[b.cage];
          const evt = await createScheduleCalendarEvent(token, calId, { ...b, cage_assigned: b.cage, player_name: b.player_name.trim() });
          gcalEventId = evt.id;
          await env.DB.prepare(`UPDATE bookings SET gcal_event_id=? WHERE id=?`).bind(gcalEventId, id).run();
        } catch(e) { console.error("GCal create error:", e.message); }
        try { await sendBookingRequestNotification({ ...b, sms_consent: smsConsent }, env, true); } catch(e) { console.error("Pedro notification error:", e.message); }
        if (b.player_email) {
          try { await sendAutoConfirmedEmail({ ...b }, id, env); } catch(e) { console.error("Player confirmation email error:", e.message); }
        }
        // SMS: member booking confirmation
        if (smsConsent && b.player_phone) {
          try {
            await sendSMS(env, b.player_phone,
              `Nitro Sports Academy: You're booked! ${cageLabel} on ${b.date} at ${b.time}. Building access code: ${env.GUEST_ACCESS_CODE}. Questions? Text Pedro at 615-870-8077. Reply STOP to opt out.`
            );
          } catch(e) { console.error("SMS member confirm error:", e.message); }
        }
        return json({ id, is_member: true }, 201);
      }

      // Non-member: require a signed waiver before holding the slot
      const waiverSigned = await hasSignedWaiver(b.player_email, env);
      if (!waiverSigned) return json({ waiver_required: true }, 412);

      const price = GUEST_CAGE_PRICES[duration] ?? GUEST_CAGE_PRICES[30];
      await env.DB.prepare(
        `INSERT INTO bookings (id,date,time,discipline,player_name,player_email,player_phone,status,cage_assigned,booking_type,duration,is_member,price,payment_status,sms_consent)
         VALUES (?,?,?,'cage_request',?,?,?,'pending_payment',?,'cage_request',?,0,?,'unpaid',?)`
      ).bind(id, b.date, b.time, b.player_name.trim(), b.player_email?.trim() || null, b.player_phone?.trim() || null, b.cage, duration, price, smsConsent).run();
      try { await upsertGuestLead(b, env); } catch(e) { console.error("Guest lead error:", e.message); }

      let paymentLinkUrl = null;
      try {
        const link = await createSquarePaymentLink(id, { ...b, cage: b.cage }, price, duration, env);
        paymentLinkUrl = link.url;
        await env.DB.prepare(`UPDATE bookings SET square_order_id=?, square_payment_link_url=? WHERE id=?`).bind(link.orderId, link.url, id).run();
      } catch(e) { console.error("Square payment link error:", e.message); }

      try { await sendBookingRequestNotification({ ...b, time: `${b.time} (GUEST — payment pending, $${price})`, sms_consent: smsConsent }, env, false); } catch(e) { console.error("Pedro notification error:", e.message); }
      if (b.player_email) {
        try { await sendGuestPaymentPendingEmail({ ...b, duration }, price, paymentLinkUrl, env); } catch(e) { console.error("Guest email error:", e.message); }
      }
      // SMS: alert Pedro about the guest booking
      try {
        await sendSMS(env, "6158708077",
          `Nitro NSA: New guest booking — ${b.player_name.trim()} reserved ${cageLabel} on ${b.date} at ${b.time}. Payment pending ($${price}).`
        );
      } catch(e) { console.error("SMS Pedro alert error:", e.message); }

      return json({ id, is_member: false, payment_required: true, price, payment_link_url: paymentLinkUrl }, 201);
    }
    if (method === "POST" && path === "/membership-signup") {
      const b = await request.json();
      const plan = b.plan;
      if (!MEMBERSHIP_PRICES[plan]) return err("Invalid plan");
      const primary = b.primary ?? {};
      if (!primary.first_name || !primary.last_name || !primary.email || !primary.phone) {
        return err("Primary member name, email, and phone are required");
      }
      const waiverInput = b.waiver ?? {};
      if (!waiverInput.signature || !waiverInput.emergency_phone || !waiverInput.participant_1_name) {
        return err("Waiver signature and emergency phone are required");
      }
      const kids = plan === "individual" ? [] : (b.kids ?? []);
      const email = primary.email.trim().toLowerCase();

      const waiverId = uuid();
      await env.DB.prepare(`
        INSERT INTO waivers
          (id, participant_1_name, participant_1_age, participant_2_name, participant_2_age,
           participant_3_name, participant_3_age, guardian_name, guardian_email, emergency_phone,
           signature, ip_address, signed_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).bind(
        waiverId, waiverInput.participant_1_name, waiverInput.participant_1_age ?? null,
        waiverInput.participant_2_name ?? null, waiverInput.participant_2_age ?? null,
        waiverInput.participant_3_name ?? null, waiverInput.participant_3_age ?? null,
        waiverInput.guardian_name ?? `${primary.first_name} ${primary.last_name}`,
        waiverInput.guardian_email ?? email,
        waiverInput.emergency_phone, waiverInput.signature,
        request.headers.get("CF-Connecting-IP") ?? null, new Date().toISOString()
      ).run();

      const price = MEMBERSHIP_PRICES[plan];
      const startDate = new Date().toISOString().slice(0, 10);
      const renewal = new Date();
      renewal.setFullYear(renewal.getFullYear() + 1);
      const renewalDate = renewal.toISOString().slice(0, 10);
      const membershipId = uuid();
      const primaryClientId = uuid();

      if (plan === "individual") {
        await env.DB.prepare(`
          INSERT INTO clients (id,first_name,last_name,email,phone,address,date_of_birth,
            current_team,years_playing,primary_position,secondary_position,
            emergency_contact_name,emergency_contact_phone,lead_status)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        `).bind(
          primaryClientId, primary.first_name, primary.last_name, email, primary.phone,
          primary.address ?? null, primary.date_of_birth ?? null, primary.current_team ?? null,
          primary.years_playing ?? null, primary.primary_position ?? null, primary.secondary_position ?? null,
          primary.emergency_contact_name ?? null, primary.emergency_contact_phone ?? null, "member"
        ).run();
        await env.DB.prepare(`
          INSERT INTO memberships (id,client_id,type,start_date,renewal_date,amount_paid,amount_due,status,notes)
          VALUES (?,?,?,?,?,?,?,?,?)
        `).bind(membershipId, primaryClientId, plan, startDate, renewalDate, 0, price, "pending_payment", "Signed up online").run();
      } else {
        const householdId = uuid();
        await env.DB.prepare("INSERT INTO households (id,name,notes) VALUES (?,?,?)")
          .bind(householdId, `${primary.last_name} Family`, null).run();
        await env.DB.prepare(`
          INSERT INTO clients (id,first_name,last_name,email,phone,address,date_of_birth,
            current_team,years_playing,primary_position,secondary_position,
            emergency_contact_name,emergency_contact_phone,household_id,household_role,lead_status)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        `).bind(
          primaryClientId, primary.first_name, primary.last_name, email, primary.phone,
          primary.address ?? null, primary.date_of_birth ?? null, primary.current_team ?? null,
          primary.years_playing ?? null, primary.primary_position ?? null, primary.secondary_position ?? null,
          primary.emergency_contact_name ?? null, primary.emergency_contact_phone ?? null,
          householdId, "contact", "member"
        ).run();
        for (const kid of kids) {
          if (!kid.first_name) continue;
          await env.DB.prepare(`
            INSERT INTO clients (id,first_name,last_name,date_of_birth,current_team,years_playing,
              primary_position,secondary_position,household_id,household_role,lead_status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
          `).bind(
            uuid(), kid.first_name, kid.last_name ?? "", kid.date_of_birth ?? null, kid.current_team ?? null,
            kid.years_playing ?? null, kid.primary_position ?? null, kid.secondary_position ?? null,
            householdId, "child", "member"
          ).run();
        }
        await env.DB.prepare(`
          INSERT INTO memberships (id,household_id,client_id,type,start_date,renewal_date,amount_paid,amount_due,status,notes)
          VALUES (?,?,NULL,?,?,?,?,?,?,?)
        `).bind(membershipId, householdId, plan, startDate, renewalDate, 0, price, "pending_payment", "Signed up online").run();
      }

      let paymentLinkUrl = null;
      try {
        const link = await createMembershipPaymentLink(membershipId, MEMBERSHIP_TYPE_LABEL[plan] ?? plan, price, email, env);
        paymentLinkUrl = link.url;
        await env.DB.prepare("UPDATE memberships SET square_order_id=? WHERE id=?").bind(link.orderId, membershipId).run();
      } catch(e) { console.error("Membership payment link error:", e.message); }

      if (!paymentLinkUrl) return err("Could not create payment link. Please contact us directly.", 500);
      return json({ membership_id: membershipId, payment_link_url: paymentLinkUrl }, 201);
    }
    if (method === "GET" && path === "/waivers/check") {
      const email = url.searchParams.get("email");
      if (!email) return err("email required");
      return json({ signed: await hasSignedWaiver(email, env) });
    }
    if (method === "GET" && path === "/slots") {
      const date = url.searchParams.get("date");
      if (!date) return err("date required");
      const discipline = url.searchParams.get("discipline");
      let q = `SELECT time, discipline, COUNT(*) as booked FROM bookings WHERE date=? AND status IN ('pending','confirmed')`;
      const params = [date];
      if (discipline) { q += ` AND discipline=?`; params.push(discipline); }
      q += ` GROUP BY time, discipline`;
      const { results } = await env.DB.prepare(q).bind(...params).all();
      return json(results);
    }
    if (method === "POST" && path === "/bookings") {
      const b = await request.json();
      if (!b.player_name) return err("player_name required");
      if (!b.date || !b.time || !b.discipline) return err("date, time, and discipline required");
      if (!["hitting", "pitching", "catching"].includes(b.discipline)) return err("invalid discipline");
      const { results: taken } = await env.DB.prepare(
        `SELECT id FROM bookings WHERE date=? AND time=? AND discipline=? AND status IN ('pending','confirmed')`
      ).bind(b.date, b.time, b.discipline).all();
      if (taken.length >= 3) return err("This slot is full", 409);
      const id = uuid();
      await env.DB.prepare(
        `INSERT INTO bookings (id,date,time,discipline,player_name,player_email,player_phone,player_age,status)
         VALUES (?,?,?,?,?,?,?,?,?)`
      ).bind(id, b.date, b.time, b.discipline, b.player_name.trim(), b.player_email?.trim() || null, b.player_phone?.trim() || null, b.player_age ? parseInt(b.player_age) : null, "pending").run();
      return json({ id }, 201);
    }
    if (method === "POST" && path === "/waivers") {
      const b = await request.json();
      if (!b.participant_1_name) return err("participant_1_name is required", 400);
      if (!b.emergency_phone) return err("emergency_phone is required", 400);
      const id = crypto.randomUUID();
      const ip = request.headers.get("CF-Connecting-IP") ?? null;
      const signed_at = new Date().toISOString();
      await env.DB.prepare(`
        INSERT INTO waivers
          (id, participant_1_name, participant_1_age,
           participant_2_name, participant_2_age,
           participant_3_name, participant_3_age,
           guardian_name, guardian_email, emergency_phone,
           signature, ip_address, signed_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).bind(
        id, b.participant_1_name, b.participant_1_age ?? null,
        b.participant_2_name ?? null, b.participant_2_age ?? null,
        b.participant_3_name ?? null, b.participant_3_age ?? null,
        b.guardian_name ?? null, b.guardian_email ?? null,
        b.emergency_phone, b.signature ?? null, ip, signed_at
      ).run();
      return json({ id, signed_at }, 201);
    }
    const leadEmailMatch = path.match(/^\/leads\/([^/]+)\/email$/);
    if (leadEmailMatch && method === "POST") {
      const b = await request.json();
      if (!b.to || !b.subject || !b.body) return err("to, subject, and body required");
      const html = `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;color:#222;max-width:600px;margin:0 auto;padding:40px 20px">
        <p style="font-size:1.1rem;line-height:1.7;margin-bottom:24px">${b.body.replace(/\n/g, "<br>")}</p>
        <hr style="border:none;border-top:1px solid #eee;margin:32px 0">
        <p style="font-size:0.85rem;color:#888">Nitro Sports Academy &middot; nitrosportsacademy.com</p>
      </body></html>`;
      const res = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          from: "Pedro Hernandez <pedro@nitrosportsacademy.com>",
          reply_to: ["coach.pedro.tn@gmail.com"],
          to: [b.to],
          bcc: ["nicholas.vastano@gmail.com"],
          subject: b.subject,
          html,
        }),
      });
      if (!res.ok) return err(`Email error: ${await res.text()}`, 500);
      return json({ ok: true });
    }
    if (method === "POST" && path === "/webhooks/square") {
      const rawBody = await request.text();
      const valid = await verifySquareSignature(request, rawBody, env);
      if (!valid) return err("Invalid signature", 401);
      const payload = JSON.parse(rawBody);
      if (payload.type === "payment.updated") {
        const payment = payload.data?.object?.payment;
        if (payment?.status === "COMPLETED" && payment.order_id) {
          const booking = await env.DB.prepare(
            "SELECT * FROM bookings WHERE square_order_id=? AND status='pending_payment'"
          ).bind(payment.order_id).first();
          if (booking) {
            let gcalEventId = null;
            try {
              const token = await getGCalToken(env);
              const calId = GCAL_CALENDARS[booking.cage_assigned];
              const evt = await createScheduleCalendarEvent(token, calId, booking);
              gcalEventId = evt.id;
            } catch(e) { console.error("GCal create error:", e.message); }
            await env.DB.prepare(`UPDATE bookings SET status='confirmed', payment_status='paid', gcal_event_id=? WHERE id=?`).bind(gcalEventId, booking.id).run();
            if (booking.player_email) {
              try { await sendAutoConfirmedEmail({ ...booking, cage: booking.cage_assigned }, booking.id, env); } catch(e) { console.error("Player confirmation email error:", e.message); }
            }
            // SMS: guest booking confirmed after payment
            if (booking.sms_consent && booking.player_phone) {
              try {
                const cageLabel = CAGE_LABEL[booking.cage_assigned] ?? booking.cage_assigned;
                await sendSMS(env, booking.player_phone,
                  `Nitro Sports Academy: Payment received — you're confirmed! ${cageLabel} on ${booking.date} at ${booking.time}. Building access code: ${env.GUEST_ACCESS_CODE}. Questions? Text 615-870-8077. Reply STOP to opt out.`
                );
              } catch(e) { console.error("SMS guest confirm error:", e.message); }
            }
          }
          const membership = await env.DB.prepare(
            "SELECT * FROM memberships WHERE square_order_id=? AND status='pending_payment'"
          ).bind(payment.order_id).first();
          if (membership) {
            const price = membership.custom_price ?? MEMBERSHIP_PRICES[membership.type] ?? 0;
            await env.DB.prepare("UPDATE memberships SET status='active', amount_paid=?, amount_due=0 WHERE id=?")
              .bind(price, membership.id).run();
            try {
              const client = membership.client_id
                ? await env.DB.prepare("SELECT * FROM clients WHERE id=?").bind(membership.client_id).first()
                : await env.DB.prepare("SELECT * FROM clients WHERE household_id=? AND household_role='contact'").bind(membership.household_id).first();
              if (client) await sendMembershipActiveNotification(client, membership, env);
            } catch(e) { console.error("Membership activation email error:", e.message); }
          }
          const renewingMembership = await env.DB.prepare(
            "SELECT * FROM memberships WHERE pending_renewal_order_id=?"
          ).bind(payment.order_id).first();
          if (renewingMembership) {
            const price = renewingMembership.custom_price ?? MEMBERSHIP_PRICES[renewingMembership.type] ?? 0;
            const prevRenewal = renewingMembership.renewal_date ? new Date(renewingMembership.renewal_date) : new Date();
            prevRenewal.setFullYear(prevRenewal.getFullYear() + 1);
            const nextRenewal = prevRenewal.toISOString().slice(0, 10);
            await env.DB.prepare(
              "UPDATE memberships SET amount_paid=?, amount_due=0, renewal_date=?, status='active', pending_renewal_order_id=NULL WHERE id=?"
            ).bind(price, nextRenewal, renewingMembership.id).run();
          }
        }
      }
      return json({ ok: true });
    }
    const claims = await requireAuth(request, env);
    if (!claims) return err("Unauthorized", 401);
    if (method === "GET" && path === "/debug/membership-check") {
      const email = (url.searchParams.get("email") ?? "").trim().toLowerCase();
      const phone = url.searchParams.get("phone") ?? "";
      const p = normalizePhone(phone);
      let byEmail = [];
      if (email) {
        const { results } = await env.DB.prepare(`SELECT c.*, m.id as m_id, m.status as m_status, m.client_id as m_client_id, m.household_id as m_household_id FROM clients c ${MEMBERSHIP_JOIN} WHERE trim(lower(c.email)) = ?`).bind(email).all();
        byEmail = results;
      }
      let byPhone = [];
      if (!byEmail.length && p) {
        const { results } = await env.DB.prepare(`SELECT c.*, m.id as m_id, m.status as m_status, m.client_id as m_client_id, m.household_id as m_household_id FROM clients c ${MEMBERSHIP_JOIN}`).all();
        byPhone = results.filter((c) => normalizePhone(c.phone) === p);
      }
      const allMatches = byEmail.length ? byEmail : byPhone;
      const matched = allMatches[0] ?? null;
      const allMembershipsForClient = matched
        ? (await env.DB.prepare("SELECT * FROM memberships WHERE client_id = ? OR household_id = ?").bind(matched.id, matched.household_id ?? "").all()).results
        : [];
      const isMember = await isActiveMember(email, phone, env);
      return json({
        query: { email, normalized_phone: p },
        matched_via: byEmail.length ? "email" : byPhone.length ? "phone" : "none",
        duplicate_client_count: allMatches.length,
        all_matching_clients: allMatches,
        matched_client: matched,
        all_memberships_for_this_client_or_household: allMembershipsForClient,
        isActiveMember_result: isMember
      });
    }
    if (method === "GET" && path === "/debug/duplicate-clients") {
      const { results: clients } = await env.DB.prepare(`
        SELECT c.id, c.first_name, c.last_name, c.email, c.phone, c.lead_status,
               c.household_id, m.status as membership_status, m.id as membership_id
        FROM clients c
        ${MEMBERSHIP_JOIN}
        ORDER BY c.last_name, c.first_name
      `).all();
      const byEmail = /* @__PURE__ */ new Map();
      const byPhone = /* @__PURE__ */ new Map();
      for (const c of clients) {
        const e = (c.email ?? "").trim().toLowerCase();
        if (e) {
          if (!byEmail.has(e)) byEmail.set(e, []);
          byEmail.get(e).push(c);
        }
        const p = normalizePhone(c.phone);
        if (p) {
          if (!byPhone.has(p)) byPhone.set(p, []);
          byPhone.get(p).push(c);
        }
      }
      const dupGroups = [];
      const seenIds = /* @__PURE__ */ new Set();
      for (const [key, group] of byEmail) {
        if (group.length > 1) {
          dupGroups.push({ matched_on: "email", value: key, clients: group });
          group.forEach((c) => seenIds.add(c.id));
        }
      }
      for (const [key, group] of byPhone) {
        if (group.length > 1 && !group.every((c) => seenIds.has(c.id))) {
          dupGroups.push({ matched_on: "phone", value: key, clients: group });
        }
      }
      const noActiveMembershipButHasDuplicate = dupGroups.filter(
        (g) => g.clients.some((c) => c.membership_status === "active") && g.clients.some((c) => c.membership_status !== "active")
      );
      return json({
        total_clients: clients.length,
        duplicate_groups_found: dupGroups.length,
        duplicate_groups: dupGroups,
        groups_with_a_silently_broken_member: noActiveMembershipButHasDuplicate
      });
    }
    if (method === "GET" && path === "/calendar/events") {
      const date = url.searchParams.get("date");
      if (!date) return err("date required");
      const noon = new Date(`${date}T12:00:00Z`);
      const chiHour = parseInt(noon.toLocaleString('en-US', { timeZone: 'America/Chicago', hour: '2-digit', hour12: false }));
      const offsetHours = 12 - chiHour;
      const timeMinMs = new Date(`${date}T00:00:00Z`).getTime() + offsetHours * 3600 * 1000;
      const timeMin = encodeURIComponent(new Date(timeMinMs).toISOString());
      const timeMax = encodeURIComponent(new Date(timeMinMs + 24 * 3600 * 1000).toISOString());
      let token;
      try { token = await getGCalToken(env); } catch(e) { return err("GCal auth failed", 500); }
      const results = await Promise.all(
        Object.entries(GCAL_CALENDARS).map(async ([cage, calId]) => {
          const res = await fetch(
            `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calId)}/events?timeMin=${timeMin}&timeMax=${timeMax}&singleEvents=true&orderBy=startTime`,
            { headers: { Authorization: `Bearer ${token}` } }
          );
          if (!res.ok) return [];
          const data = await res.json();
          return (data.items ?? []).map(e => ({
            cage,
            cageLabel: CAGE_LABEL[cage],
            id: e.id,
            summary: e.summary ?? "",
            start: e.start?.dateTime ?? e.start?.date ?? null,
            end: e.end?.dateTime ?? e.end?.date ?? null,
          }));
        })
      );
      return json(results.flat());
    }
    if (method === "GET" && path === "/households") {
      const search = url.searchParams.get("search") ?? "";
      let q = `SELECT h.*, COUNT(c.id) as member_count FROM households h LEFT JOIN clients c ON c.household_id = h.id`;
      const params = [];
      if (search) { q += ` WHERE h.name LIKE ?`; params.push(`%${search}%`); }
      q += ` GROUP BY h.id ORDER BY h.name`;
      const stmt = params.length ? env.DB.prepare(q).bind(...params) : env.DB.prepare(q);
      const { results } = await stmt.all();
      return json(results);
    }
    if (method === "POST" && path === "/households") {
      const b = await request.json();
      const id = uuid();
      await env.DB.prepare("INSERT INTO households (id,name,notes) VALUES (?,?,?)").bind(id, b.name, b.notes ?? null).run();
      return json(await env.DB.prepare("SELECT * FROM households WHERE id = ?").bind(id).first(), 201);
    }
    const householdMatch = path.match(/^\/households\/([^/]+)$/);
    if (householdMatch) {
      const hid = householdMatch[1];
      if (method === "GET") {
        const household = await env.DB.prepare("SELECT * FROM households WHERE id = ?").bind(hid).first();
        if (!household) return err("Household not found", 404);
        const { results: members } = await env.DB.prepare(
          `SELECT c.*, m.type as membership_type, m.status as membership_status,
                  m.renewal_date, m.amount_due, m.amount_paid, m.custom_price, m.id as membership_id
           FROM clients c
           ${MEMBERSHIP_JOIN}
           WHERE c.household_id = ? ORDER BY c.household_role DESC, c.first_name`
        ).bind(hid).all();
        members.forEach(r => { if (r.membership_id) r.amount_due = computeMembershipDue({ custom_price: r.custom_price, type: r.membership_type, renewal_date: r.renewal_date, status: r.membership_status }); });
        const membership = await env.DB.prepare(
          "SELECT * FROM memberships WHERE household_id = ? ORDER BY (status = 'active') DESC, created_at DESC LIMIT 1"
        ).bind(hid).first();
        if (membership) membership.amount_due = computeMembershipDue(membership);
        return json({ ...household, members, membership: membership ?? null });
      }
      if (method === "PUT") {
        const b = await request.json();
        await env.DB.prepare("UPDATE households SET name=?,notes=? WHERE id=?").bind(b.name, b.notes ?? null, hid).run();
        return json(await env.DB.prepare("SELECT * FROM households WHERE id = ?").bind(hid).first());
      }
      if (method === "DELETE") {
        await env.DB.prepare("UPDATE clients SET household_id=NULL, household_role=NULL WHERE household_id=?").bind(hid).run();
        await env.DB.prepare("DELETE FROM households WHERE id=?").bind(hid).run();
        return json({ ok: true });
      }
    }
    const householdMemMatch = path.match(/^\/households\/([^/]+)\/memberships$/);
    if (householdMemMatch && method === "POST") {
      const hid = householdMemMatch[1];
      const b = await request.json();
      const id = uuid();
      const price = MEMBERSHIP_PRICES[b.type] ?? 0;
      const amountDue = Math.max(0, price - (b.amount_paid ?? 0));
      await env.DB.prepare(
        "INSERT INTO memberships (id,household_id,client_id,type,start_date,renewal_date,amount_paid,amount_due,status,notes) VALUES (?,?,NULL,?,?,?,?,?,?,?)"
      ).bind(id, hid, b.type, b.start_date ?? null, b.renewal_date ?? null, b.amount_paid ?? 0, amountDue, b.status ?? "active", b.notes ?? null).run();
      return json(await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(id).first(), 201);
    }
    if (method === "GET" && path === "/clients") {
      const search = url.searchParams.get("search") ?? "";
      const status = url.searchParams.get("status") ?? "";
      let q = `
        SELECT c.*, h.name as household_name,
          m.type as membership_type, m.status as membership_status,
          m.renewal_date, m.amount_due, m.amount_paid, m.custom_price, m.id as membership_id
        FROM clients c
        LEFT JOIN households h ON h.id = c.household_id
        ${MEMBERSHIP_JOIN}
      `;
      const params = [];
      const where = [];
      if (search) {
        where.push(`(c.first_name LIKE ? OR c.last_name LIKE ? OR c.email LIKE ? OR c.current_team LIKE ? OR h.name LIKE ?)`);
        const s = `%${search}%`;
        params.push(s, s, s, s, s);
      }
      if (status) { where.push(`m.status = ?`); params.push(status); }
      if (where.length) q += ` WHERE ${where.join(" AND ")}`;
      q += ` ORDER BY c.last_name, c.first_name`;
      const stmt = params.length ? env.DB.prepare(q).bind(...params) : env.DB.prepare(q);
      const { results } = await stmt.all();
      results.forEach(r => { if (r.membership_id) r.amount_due = computeMembershipDue({ custom_price: r.custom_price, type: r.membership_type, renewal_date: r.renewal_date, status: r.membership_status }); });
      return json(results);
    }
    if (method === "GET" && path === "/leads") {
      const { results } = await env.DB.prepare(`
        SELECT * FROM clients
        WHERE lead_status IN ('lead','contacted')
        ORDER BY created_at DESC
      `).all();
      return json(results);
    }
    if (method === "POST" && path === "/clients") {
      const b = await request.json();
      const email = (b.email ?? "").trim().toLowerCase();
      if (email) {
        const existing = await env.DB.prepare("SELECT id, lead_status FROM clients WHERE trim(lower(email)) = ?").bind(email).first();
        if (existing) {
          if (existing.lead_status !== "lead") {
            return err(`A client with this email already exists (id ${existing.id}). Edit that client instead of creating a duplicate.`, 409);
          }
          const accessCode = (b.access_code ?? "").trim() || null;
          if (accessCode) await assertAccessCodeAvailable(accessCode, env, existing.id);
          await env.DB.prepare(`
            UPDATE clients SET first_name=?,last_name=?,email=?,phone=?,address=?,date_of_birth=?,
              current_team=?,years_playing=?,primary_position=?,secondary_position=?,
              emergency_contact_name=?,emergency_contact_phone=?,household_id=?,household_role=?,
              lead_status=?,inquiry_type=?,inquiry_notes=?,access_code=?
            WHERE id=?
          `).bind(
            b.first_name, b.last_name, b.email ?? null, b.phone ?? null,
            b.address ?? null, b.date_of_birth ?? null, b.current_team ?? null,
            b.years_playing ?? null, b.primary_position ?? null, b.secondary_position ?? null,
            b.emergency_contact_name ?? null, b.emergency_contact_phone ?? null,
            b.household_id ?? null, b.household_role ?? null,
            b.lead_status ?? null, b.inquiry_type ?? null, b.inquiry_notes ?? null, accessCode,
            existing.id
          ).run();
          return json(await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(existing.id).first());
        }
      }
      const id = uuid();
      const accessCode = (b.access_code ?? "").trim() || null;
      if (accessCode) await assertAccessCodeAvailable(accessCode, env, null);
      await env.DB.prepare(`
        INSERT INTO clients (id,first_name,last_name,email,phone,address,date_of_birth,
          current_team,years_playing,primary_position,secondary_position,
          emergency_contact_name,emergency_contact_phone,household_id,household_role,
          lead_status,inquiry_type,inquiry_notes,access_code)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `).bind(
        id, b.first_name, b.last_name, b.email ?? null, b.phone ?? null,
        b.address ?? null, b.date_of_birth ?? null, b.current_team ?? null,
        b.years_playing ?? null, b.primary_position ?? null, b.secondary_position ?? null,
        b.emergency_contact_name ?? null, b.emergency_contact_phone ?? null,
        b.household_id ?? null, b.household_role ?? null,
        b.lead_status ?? null, b.inquiry_type ?? null, b.inquiry_notes ?? null, accessCode
      ).run();
      return json(await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(id).first(), 201);
    }
    const setCodeMatch = path.match(/^\/clients\/([^/]+)\/access-code$/);
    if (setCodeMatch && method === "POST") {
      const cid = setCodeMatch[1];
      const client = await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(cid).first();
      if (!client) return err("Client not found", 404);
      if (client.access_code) return err("This client already has an access code and it cannot be changed", 409);
      const b = await request.json();
      const accessCode = (b.access_code ?? "").trim();
      if (!accessCode) return err("access_code is required");
      await assertAccessCodeAvailable(accessCode, env, cid);
      await env.DB.prepare("UPDATE clients SET access_code=? WHERE id=?").bind(accessCode, cid).run();
      return json(await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(cid).first());
    }
    const clientMatch = path.match(/^\/clients\/([^/]+)$/);
    if (clientMatch) {
      const clientId = clientMatch[1];
      if (method === "GET") {
        const client = await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(clientId).first();
        if (!client) return err("Client not found", 404);
        const membership = await env.DB.prepare(
          `SELECT * FROM memberships WHERE client_id = ? OR household_id = ? ORDER BY (status = 'active') DESC, created_at DESC LIMIT 1`
        ).bind(clientId, client.household_id ?? "").first();
        if (membership) membership.amount_due = computeMembershipDue(membership);
        const household = client.household_id
          ? await env.DB.prepare("SELECT * FROM households WHERE id = ?").bind(client.household_id).first()
          : null;
        let householdMembers = [];
        if (client.household_id) {
          const r = await env.DB.prepare(
            "SELECT id,first_name,last_name,household_role,email,phone FROM clients WHERE household_id = ? ORDER BY household_role DESC, first_name"
          ).bind(client.household_id).all();
          householdMembers = r.results;
        }
        return json({ ...client, membership: membership ?? null, household, householdMembers });
      }
      if (method === "PUT") {
        const b = await request.json();
        await env.DB.prepare(`
          UPDATE clients SET first_name=?,last_name=?,email=?,phone=?,address=?,date_of_birth=?,
            current_team=?,years_playing=?,primary_position=?,secondary_position=?,
            emergency_contact_name=?,emergency_contact_phone=?,household_id=?,household_role=?,
            lead_status=?,inquiry_type=?,inquiry_notes=?
          WHERE id=?
        `).bind(
          b.first_name, b.last_name, b.email ?? null, b.phone ?? null,
          b.address ?? null, b.date_of_birth ?? null, b.current_team ?? null,
          b.years_playing ?? null, b.primary_position ?? null, b.secondary_position ?? null,
          b.emergency_contact_name ?? null, b.emergency_contact_phone ?? null,
          b.household_id ?? null, b.household_role ?? null,
          b.lead_status ?? null, b.inquiry_type ?? null, b.inquiry_notes ?? null,
          clientId
        ).run();
        return json(await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(clientId).first());
      }
      if (method === "DELETE") {
        await env.DB.prepare("DELETE FROM payments WHERE client_id = ?").bind(clientId).run();
        await env.DB.prepare("DELETE FROM memberships WHERE client_id = ?").bind(clientId).run();
        await env.DB.prepare("DELETE FROM clients WHERE id = ?").bind(clientId).run();
        return json({ ok: true });
      }
    }
    const membershipMatch = path.match(/^\/clients\/([^/]+)\/memberships$/);
    if (membershipMatch && method === "POST") {
      const clientId = membershipMatch[1];
      const b = await request.json();
      const id = uuid();
      const price = MEMBERSHIP_PRICES[b.type] ?? 0;
      const amountDue = Math.max(0, price - (b.amount_paid ?? 0));
      await env.DB.prepare(
        "INSERT INTO memberships (id,client_id,type,start_date,renewal_date,amount_paid,amount_due,status,notes) VALUES (?,?,?,?,?,?,?,?,?)"
      ).bind(id, clientId, b.type, b.start_date ?? null, b.renewal_date ?? null, b.amount_paid ?? 0, amountDue, b.status ?? "active", b.notes ?? null).run();
      return json(await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(id).first(), 201);
    }
    const markPaidMatch = path.match(/^\/memberships\/([^/]+)\/mark-paid$/);
    if (markPaidMatch && method === "POST") {
      const mid = markPaidMatch[1];
      const m = await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(mid).first();
      if (!m) return err("Membership not found", 404);
      const price = m.custom_price ?? MEMBERSHIP_PRICES[m.type] ?? 0;
      const prevRenewal = m.renewal_date ? new Date(m.renewal_date) : new Date();
      prevRenewal.setFullYear(prevRenewal.getFullYear() + 1);
      const nextRenewal = prevRenewal.toISOString().slice(0, 10);
      await env.DB.prepare(
        "UPDATE memberships SET amount_paid=?, amount_due=0, renewal_date=?, status='active' WHERE id=?"
      ).bind(price, nextRenewal, mid).run();
      return json(await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(mid).first());
    }
    const renewalLinkMatch = path.match(/^\/memberships\/([^/]+)\/renewal-link$/);
    if (renewalLinkMatch && method === "POST") {
      const mid = renewalLinkMatch[1];
      const m = await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(mid).first();
      if (!m) return err("Membership not found", 404);
      const client = m.client_id
        ? await env.DB.prepare("SELECT * FROM clients WHERE id = ?").bind(m.client_id).first()
        : await env.DB.prepare("SELECT * FROM clients WHERE household_id = ? AND household_role = 'contact'").bind(m.household_id).first();
      if (!client) return err("Could not find a client to bill for this membership", 404);
      const price = m.custom_price ?? MEMBERSHIP_PRICES[m.type] ?? 0;
      const planLabel = MEMBERSHIP_TYPE_LABEL[m.type] ?? m.type;
      const link = await createMembershipPaymentLink(mid, planLabel, price, client.email, env);
      await env.DB.prepare("UPDATE memberships SET pending_renewal_order_id=? WHERE id=?").bind(link.orderId, mid).run();
      const firstName = client.first_name ?? "there";
      const emailSubject = `Time to renew your Nitro Sports Academy membership`;
      const emailBody = `Hi ${firstName},\n\nYour ${planLabel} membership ($${price.toFixed(2)}) is due for renewal. You can pay securely here:\n${link.url}\n\nOnce paid, your access stays active without any interruption. Let us know if you have any questions!\n\n- Pedro\nNitro Sports Academy`;
      const textBody = `Hi ${firstName}, this is Pedro at Nitro Sports Academy. Your ${planLabel} membership ($${price.toFixed(2)}) is due for renewal. Pay here to keep your access active: ${link.url}`;
      return json({
        url: link.url,
        order_id: link.orderId,
        client_name: `${client.first_name} ${client.last_name}`,
        client_email: client.email,
        client_phone: client.phone,
        price,
        plan_label: planLabel,
        email_subject: emailSubject,
        email_body: emailBody,
        text_body: textBody
      });
    }
    const membershipDeleteMatch = path.match(/^\/memberships\/([^/]+)$/);
    if (membershipDeleteMatch) {
      const mid = membershipDeleteMatch[1];
      if (method === "PUT") {
        const b = await request.json();
        const effectivePrice = b.custom_price != null ? b.custom_price : MEMBERSHIP_PRICES[b.type] ?? 0;
        const amountDue = Math.max(0, effectivePrice - (b.amount_paid ?? 0));
        await env.DB.prepare(`
          UPDATE memberships
          SET type=?, start_date=?, renewal_date=?, custom_price=?,
              amount_paid=?, amount_due=?, status=?, notes=?
          WHERE id=?
        `).bind(b.type, b.start_date ?? null, b.renewal_date ?? null, b.custom_price ?? null, b.amount_paid ?? 0, amountDue, b.status ?? "active", b.notes ?? null, mid).run();
        return json(await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(mid).first());
      }
      if (method === "DELETE") {
        await env.DB.prepare("DELETE FROM memberships WHERE id = ?").bind(mid).run();
        return json({ ok: true });
      }
    }
    const paymentDeleteMatch = path.match(/^\/payments\/([^/]+)$/);
    if (paymentDeleteMatch && method === "DELETE") {
      const pid = paymentDeleteMatch[1];
      const payment = await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(pid).first();
      if (payment?.membership_id) {
        const m = await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(payment.membership_id).first();
        if (m) {
          const newPaid = Math.max(0, (m.amount_paid ?? 0) - payment.amount);
          const effectivePrice = m.custom_price ?? MEMBERSHIP_PRICES[m.type] ?? 0;
          const newDue = Math.max(0, effectivePrice - newPaid);
          await env.DB.prepare("UPDATE memberships SET amount_paid=?,amount_due=? WHERE id=?").bind(newPaid, newDue, payment.membership_id).run();
        }
      }
      await env.DB.prepare("DELETE FROM payments WHERE id = ?").bind(pid).run();
      return json({ ok: true });
    }
    // GET /clients/:id/cage-bookings — booking history for one client
    const cageBookingsMatch = path.match(/^\/clients\/([^/]+)\/cage-bookings$/);
    if (cageBookingsMatch && method === "GET") {
      const cid = cageBookingsMatch[1];
      const { results } = await env.DB.prepare(`
        SELECT id, date, time, cage_assigned, duration, status, payment_status, price, created_at
        FROM bookings
        WHERE client_id = ? AND booking_type = 'cage_request'
        ORDER BY date DESC, time DESC
      `).bind(cid).all();
      return json(results);
    }

    // GET /bookings/summary?range=week|month&date=YYYY-MM-DD — per-member booking counts
    if (path === "/bookings/summary" && method === "GET") {
      const range = url.searchParams.get("range") ?? "month";
      const dateParam = url.searchParams.get("date") ?? new Date().toISOString().slice(0, 10);
      const [y, mo, d] = dateParam.split("-").map(Number);
      let start, end;
      if (range === "week") {
        const base = new Date(Date.UTC(y, mo - 1, d));
        const day = base.getUTCDay();
        const mon = new Date(base); mon.setUTCDate(base.getUTCDate() - (day === 0 ? 6 : day - 1));
        const sun = new Date(mon); sun.setUTCDate(mon.getUTCDate() + 6);
        start = mon.toISOString().slice(0, 10);
        end = sun.toISOString().slice(0, 10);
      } else {
        start = `${y}-${String(mo).padStart(2,"0")}-01`;
        const lastDay = new Date(Date.UTC(y, mo, 0)).getUTCDate();
        end = `${y}-${String(mo).padStart(2,"0")}-${lastDay}`;
      }
      // Members — linked to a client record
      const { results: memberRows } = await env.DB.prepare(`
        SELECT
          b.client_id,
          c.first_name, c.last_name, c.email,
          'member' as booker_type,
          COUNT(*) as total_bookings,
          SUM(b.duration) as total_minutes,
          GROUP_CONCAT(b.cage_assigned || ':' || b.date || ':' || b.time, '|') as booking_detail
        FROM bookings b
        JOIN clients c ON c.id = b.client_id
        WHERE b.booking_type = 'cage_request'
          AND b.status IN ('confirmed','pending_payment')
          AND b.date >= ? AND b.date <= ?
          AND b.client_id IS NOT NULL
        GROUP BY b.client_id
        ORDER BY total_bookings DESC
      `).bind(start, end).all();
      // Unlinked bookings — client_id IS NULL; classify by whether email matches a client record
      const { results: unlinkedRows } = await env.DB.prepare(`
        SELECT
          c.id as client_id,
          c.first_name, c.last_name, c.email,
          b.player_name, b.player_email,
          b.cage_assigned, b.date, b.time, b.duration
        FROM bookings b
        LEFT JOIN clients c ON trim(lower(c.email)) = trim(lower(b.player_email))
        WHERE b.booking_type = 'cage_request'
          AND b.status IN ('confirmed','pending_payment')
          AND b.date >= ? AND b.date <= ?
          AND b.client_id IS NULL
      `).bind(start, end).all();

      // Group unlinked rows — those with a matched client_id are members, rest are guests
      const unlinkedMap = new Map();
      for (const r of unlinkedRows) {
        const key = r.client_id ?? (r.player_email?.toLowerCase() ?? r.player_name);
        if (!unlinkedMap.has(key)) {
          unlinkedMap.set(key, {
            client_id: r.client_id ?? null,
            first_name: r.client_id ? r.first_name : r.player_name,
            last_name: r.client_id ? r.last_name : '',
            email: r.client_id ? r.email : r.player_email,
            booker_type: r.client_id ? 'member' : 'guest',
            total_bookings: 0,
            total_minutes: 0,
            booking_details: [],
          });
        }
        const entry = unlinkedMap.get(key);
        entry.total_bookings += 1;
        entry.total_minutes += (r.duration ?? 0);
        entry.booking_details.push(`${r.cage_assigned}:${r.date}:${r.time}`);
      }
      const unlinkedGrouped = [...unlinkedMap.values()].map(e => ({
        ...e,
        booking_detail: e.booking_details.join('|'),
      }));

      // Merge unlinked members into memberRows (add to existing or append)
      const memberMap = new Map(memberRows.map(r => [r.client_id, r]));
      for (const u of unlinkedGrouped) {
        if (u.booker_type === 'member' && u.client_id) {
          if (memberMap.has(u.client_id)) {
            const existing = memberMap.get(u.client_id);
            existing.total_bookings += u.total_bookings;
            existing.total_minutes += u.total_minutes;
            existing.booking_detail += (existing.booking_detail ? '|' : '') + u.booking_detail;
          } else {
            memberMap.set(u.client_id, u);
          }
        }
      }
      const guestRows = unlinkedGrouped.filter(u => u.booker_type === 'guest');
      const rows = [...memberMap.values(), ...guestRows].sort((a, b) => b.total_bookings - a.total_bookings);
      return json({ range, start, end, rows });
    }

    const paymentsMatch = path.match(/^\/clients\/([^/]+)\/payments$/);
    if (paymentsMatch) {
      const clientId = paymentsMatch[1];
      if (method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT * FROM payments WHERE client_id = ? ORDER BY date DESC"
        ).bind(clientId).all();
        return json(results);
      }
      if (method === "POST") {
        const b = await request.json();
        const id = uuid();
        await env.DB.prepare(
          "INSERT INTO payments (id,client_id,membership_id,amount,date,method,venmo_reference,notes) VALUES (?,?,?,?,?,?,?,?)"
        ).bind(id, clientId, b.membership_id ?? null, b.amount, b.date, b.method ?? "venmo", b.venmo_reference ?? null, b.notes ?? null).run();
        if (b.membership_id) {
          const m = await env.DB.prepare("SELECT * FROM memberships WHERE id = ?").bind(b.membership_id).first();
          if (m) {
            const newPaid = (m.amount_paid ?? 0) + b.amount;
            const effectivePrice = m.custom_price ?? MEMBERSHIP_PRICES[m.type] ?? 0;
            const newDue = Math.max(0, effectivePrice - newPaid);
            await env.DB.prepare("UPDATE memberships SET amount_paid=?,amount_due=?,status=? WHERE id=?").bind(newPaid, newDue, newDue <= 0 ? "active" : m.status, b.membership_id).run();
          }
        }
        return json(await env.DB.prepare("SELECT * FROM payments WHERE id = ?").bind(id).first(), 201);
      }
    }
    if (method === "GET" && path === "/renewals/upcoming") {
      const days = parseInt(url.searchParams.get("days") ?? "30");
      const cutoff = new Date(Date.now() + days * 864e5).toISOString().slice(0, 10);
      // Include: renewals due within window OR any active membership with a balance due
      const { results: individual } = await env.DB.prepare(`
        SELECT c.id, c.first_name, c.last_name, c.email, c.phone,
               m.id as membership_id, m.type, m.renewal_date, m.amount_due, m.custom_price, m.status,
               NULL as household_id, NULL as household_name
        FROM clients c JOIN memberships m ON m.client_id = c.id
        WHERE m.status = 'active'
          AND (m.renewal_date <= ? OR m.amount_due > 0)
          AND m.id = (SELECT id FROM memberships WHERE client_id = c.id ORDER BY created_at DESC LIMIT 1)
      `).bind(cutoff).all();
      const { results: household } = await env.DB.prepare(`
        SELECT c.id, c.first_name, c.last_name, c.email, c.phone,
               m.id as membership_id, m.type, m.renewal_date, m.amount_due, m.custom_price, m.status,
               h.id as household_id, h.name as household_name
        FROM memberships m
        JOIN households h ON h.id = m.household_id
        JOIN clients c ON c.household_id = h.id AND c.household_role = 'contact'
        WHERE m.status = 'active'
          AND (m.renewal_date <= ? OR m.amount_due > 0)
          AND m.id = (SELECT id FROM memberships WHERE household_id = h.id ORDER BY created_at DESC LIMIT 1)
      `).bind(cutoff).all();
      const seen = new Set();
      const all = [...individual, ...household]
        .filter(r => { if (seen.has(r.membership_id)) return false; seen.add(r.membership_id); return true; })
        .sort((a, b) => (a.renewal_date ?? '').localeCompare(b.renewal_date ?? ''));
      all.forEach(r => { r.amount_due = computeMembershipDue(r); });
      return json(all);
    }
    if (method === "GET" && path === "/waivers") {
      const { results } = await env.DB.prepare(`SELECT * FROM waivers ORDER BY signed_at DESC`).all();
      return json(results);
    }
    if (method === "GET" && path === "/bookings") {
      const status = url.searchParams.get("status") ?? "";
      const date = url.searchParams.get("date") ?? "";
      const type = url.searchParams.get("type") ?? "";
      let q = `SELECT * FROM bookings WHERE 1=1`;
      const params = [];
      if (status) { q += ` AND status=?`; params.push(status); }
      if (date) { q += ` AND date=?`; params.push(date); }
      if (type) { q += ` AND booking_type=?`; params.push(type); }
      q += ` ORDER BY date ASC, time ASC, created_at ASC`;
      const stmt = params.length ? env.DB.prepare(q).bind(...params) : env.DB.prepare(q);
      const { results } = await stmt.all();
      return json(results);
    }
    const approveMatch = path.match(/^\/bookings\/([^/]+)\/approve$/);
    if (approveMatch && method === "PUT") {
      const bid = approveMatch[1];
      const booking = await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first();
      if (!booking) return err("Booking not found", 404);
      if (booking.status === "confirmed") return err("Already confirmed");
      const isCageRequest = booking.booking_type === "cage_request";
      const cage = isCageRequest ? booking.cage_assigned : await pickCage(env.DB, booking.date, booking.time, booking.discipline);
      const calId = GCAL_CALENDARS[cage];
      let eventId = null;
      try {
        const token = await getGCalToken(env);
        const evt = isCageRequest
          ? await createScheduleCalendarEvent(token, calId, { ...booking, cage_assigned: cage })
          : await createCalendarEvent(token, calId, { ...booking, cage_assigned: cage });
        eventId = evt.id;
      } catch(e) { console.error("GCal create error:", e.message); }
      await env.DB.prepare(`UPDATE bookings SET status='confirmed', cage_assigned=?, gcal_event_id=? WHERE id=?`).bind(cage, eventId, bid).run();
      return json(await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first());
    }
    const confirmPaymentMatch = path.match(/^\/bookings\/([^/]+)\/confirm-payment$/);
    if (confirmPaymentMatch && method === "PUT") {
      const bid = confirmPaymentMatch[1];
      const booking = await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first();
      if (!booking) return err("Booking not found", 404);
      if (booking.status !== "pending_payment") return err("Booking is not awaiting payment");
      let gcalEventId = null;
      try {
        const token = await getGCalToken(env);
        const calId = GCAL_CALENDARS[booking.cage_assigned];
        const evt = await createScheduleCalendarEvent(token, calId, booking);
        gcalEventId = evt.id;
      } catch(e) { console.error("GCal create error:", e.message); }
      await env.DB.prepare(`UPDATE bookings SET status='confirmed', payment_status='paid', gcal_event_id=? WHERE id=?`).bind(gcalEventId, bid).run();
      const updated = await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first();
      if (updated.player_email) {
        try { await sendAutoConfirmedEmail({ ...updated, cage: updated.cage_assigned }, bid, env); } catch(e) { console.error("Player confirmation email error:", e.message); }
      }
      return json(updated);
    }
    const declineMatch = path.match(/^\/bookings\/([^/]+)\/decline$/);
    if (declineMatch && method === "PUT") {
      const bid = declineMatch[1];
      const booking = await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first();
      if (booking?.player_email) {
        try { await sendCancellationEmail(booking, env); } catch(e) { console.error("Cancellation email error:", e.message); }
      }
      await env.DB.prepare(`UPDATE bookings SET status='declined' WHERE id=?`).bind(bid).run();
      return json(await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first());
    }
    const bookingDelMatch = path.match(/^\/bookings\/([^/]+)$/);
    if (bookingDelMatch && method === "DELETE") {
      const bid = bookingDelMatch[1];
      const booking = await env.DB.prepare("SELECT * FROM bookings WHERE id=?").bind(bid).first();
      if (!booking) return err("Booking not found", 404);
      if (booking.player_email && booking.status === "confirmed") {
        try { await sendCancellationEmail(booking, env); } catch(e) { console.error("Cancellation email error:", e.message); }
      }
      if (booking.gcal_event_id && booking.cage_assigned) {
        try {
          const token = await getGCalToken(env);
          await deleteCalendarEvent(token, GCAL_CALENDARS[booking.cage_assigned], booking.gcal_event_id);
        } catch(e) { console.error("GCal delete error:", e.message); }
      }
      await env.DB.prepare("DELETE FROM bookings WHERE id=?").bind(bid).run();
      return json({ ok: true });
    }
    return err("Not found", 404);
  }
};
export {
  src_default as default
};
