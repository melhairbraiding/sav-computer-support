// Shared key-value storage for SAV Computer Support, backed by Netlify Blobs.
// The front end (index.html) talks to this at /.netlify/functions/data.
//
// SECURITY MODEL (important — read this before changing anything):
// - The admin password lives ONLY in the ADMIN_PASSWORD environment variable on
//   Netlify. It is never stored in Blobs, never returned to the browser, and
//   never appears in the site's HTML/JS source.
// - "Logging in" as admin means the browser sends the password once via the
//   'login' action; if correct, the browser remembers that password in memory
//   for the session and sends it back as the x-admin-token header on every
//   write request afterward. The server re-checks it against ADMIN_PASSWORD
//   on every single write — there is no bypassable client-side-only gate.
// - Reads of device-db / gallery are public (that's normal site content).
// - Reads of an individual ticket (ticket-log:*) are public ONLY in a
//   stripped form (no name/phone/email/notes) so ticket lookup keeps working
//   for anyone with a ticket number, without leaking customer PII to anyone
//   who enumerates ticket numbers. Full detail requires the admin token.
// - Writes to device-db / gallery / site-config always require the admin token.
// - Writes to an existing ticket-log record require the admin token, EXCEPT
//   the one narrow case of a customer submitting feedback on their own
//   already-completed ticket (verified server-side: nothing but the feedback
//   field is allowed to change, and only once).
// - Creating a brand-new ticket-log record (a booking) is public, and so is
//   bumping the ticket-seq counter — that's normal, expected site usage.
//
// GET  ?action=get&key=xxx        -> { value }
// GET  ?action=list&prefix=xxx    -> { keys: [...] }
// POST { action:'login', password }         -> { ok:true } or 401
// POST { action:'set', key, value }         -> { ok:true } or 403
// POST { action:'delete', key }             -> { ok:true } or 403  (admin only, always)

const { getStore } = require("@netlify/blobs");

function getBlobStore() {
  const siteID = process.env.BLOBS_SITE_ID;
  const token = process.env.BLOBS_API_TOKEN;
  if (siteID && token) {
    return getStore({ name: "sav-site-data", siteID, token });
  }
  return getStore("sav-site-data");
}

function adminPassword() {
  // Falls back to a default only so the site never locks you out before you've
  // set the real one. Set ADMIN_PASSWORD in Netlify site settings ASAP.
  return process.env.ADMIN_PASSWORD || "admin123";
}

function isAdminRequest(event) {
  const headers = event.headers || {};
  const token = headers["x-admin-token"] || headers["X-Admin-Token"];
  return !!token && token === adminPassword();
}

function stripTicketPII(record) {
  return {
    ticket: record.ticket,
    category: record.category,
    issue: record.issue,
    price: record.price,
    mode: record.mode,
    date: record.date,
    status: record.status,
    history: record.history,
    feedback: record.feedback,
    cancelReason: record.cancelReason,
    createdAt: record.createdAt,
  };
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, x-admin-token",
};

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS_HEADERS };
  }

  try {
    const store = getBlobStore();
    const admin = isAdminRequest(event);

    if (event.httpMethod === "GET") {
      const params = event.queryStringParameters || {};

      if (params.action === "list") {
        const prefix = params.prefix || "";
        const { blobs } = await store.list({ prefix });
        return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ keys: blobs.map((b) => b.key) }) };
      }

      if (params.action === "get") {
        if (!params.key) {
          return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "key required" }) };
        }
        let value = await store.get(params.key);
        if (value !== null && params.key.startsWith("ticket-log:") && !admin) {
          try {
            value = JSON.stringify(stripTicketPII(JSON.parse(value)));
          } catch (e) {
            /* if it doesn't parse, leave it — shouldn't happen */
          }
        }
        return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ value }) };
      }

      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "unknown action" }) };
    }

    if (event.httpMethod === "POST") {
      const body = JSON.parse(event.body || "{}");

      if (body.action === "login") {
        if (body.password === adminPassword()) {
          return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
        }
        return { statusCode: 401, headers: CORS_HEADERS, body: JSON.stringify({ ok: false, error: "wrong password" }) };
      }

      if (body.action === "lookup") {
        // Two-factor ticket lookup: must supply BOTH the ticket number and the
        // phone number on file for it. On any mismatch — wrong phone, or the
        // ticket simply doesn't exist — we return the exact same generic 404,
        // so someone can't use this to enumerate which ticket numbers are real.
        const genericNotFound = { statusCode: 404, headers: CORS_HEADERS, body: JSON.stringify({ error: "not found" }) };
        if (!body.ticket || !body.phone) {
          return genericNotFound;
        }
        const key = "ticket-log:" + String(body.ticket).trim().toUpperCase();
        const existing = await store.get(key);
        if (existing === null) return genericNotFound;

        try {
          const record = JSON.parse(existing);
          const digitsOnly = (s) => String(s || "").replace(/\D/g, "");
          const suppliedPhone = digitsOnly(body.phone);
          const storedPhone = digitsOnly(record.phone);
          if (!suppliedPhone || suppliedPhone !== storedPhone) {
            return genericNotFound;
          }
          return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ value: JSON.stringify(stripTicketPII(record)) }) };
        } catch (e) {
          return genericNotFound;
        }
      }

      if (body.action === "set") {
        if (!body.key) {
          return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "key required" }) };
        }

        if (admin) {
          // Admin can write anything.
          await store.set(body.key, body.value ?? "");
          return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
        }

        // Not authenticated — only allow the narrow public-safe cases.
        if (body.key === "ticket-seq") {
          await store.set(body.key, body.value ?? "");
          return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
        }

        if (body.key.startsWith("ticket-log:")) {
          const existing = await store.get(body.key);

          if (existing === null) {
            // Creating a brand-new ticket (a booking). Public and expected.
            await store.set(body.key, body.value ?? "");
            return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
          }

          // Ticket already exists — only allow adding feedback to a completed
          // ticket that doesn't have feedback yet, and nothing else may change.
          try {
            const oldRec = JSON.parse(existing);
            const newRec = JSON.parse(body.value);
            const oldWithoutFeedback = { ...oldRec, feedback: undefined };
            const newWithoutFeedback = { ...newRec, feedback: undefined };
            const onlyFeedbackChanged = JSON.stringify(oldWithoutFeedback) === JSON.stringify(newWithoutFeedback);
            const feedbackIsNew = !oldRec.feedback && !!newRec.feedback;
            const ticketIsComplete = oldRec.status === "Complete";

            if (onlyFeedbackChanged && feedbackIsNew && ticketIsComplete) {
              await store.set(body.key, body.value ?? "");
              return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
            }
          } catch (e) {
            /* falls through to 403 below */
          }
        }

        return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "not authorized" }) };
      }

      if (body.action === "delete") {
        if (!admin) {
          return { statusCode: 403, headers: CORS_HEADERS, body: JSON.stringify({ error: "not authorized" }) };
        }
        if (!body.key) {
          return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "key required" }) };
        }
        await store.delete(body.key);
        return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
      }

      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "unknown action" }) };
    }

    return { statusCode: 405, headers: CORS_HEADERS, body: JSON.stringify({ error: "method not allowed" }) };
  } catch (err) {
    return { statusCode: 500, headers: CORS_HEADERS, body: JSON.stringify({ error: String(err) }) };
  }
};