// Shared key-value storage for SAV Computer Support, backed by Netlify Blobs.
// The front end (index.html) talks to this at /.netlify/functions/data.
// GET  ?action=get&key=xxx        -> { value } (value is null if not found)
// GET  ?action=list&prefix=xxx    -> { keys: [...] }
// POST { action:'set', key, value }    -> { ok:true }
// POST { action:'delete', key }        -> { ok:true }

const { getStore } = require("@netlify/blobs");

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: CORS_HEADERS };
  }

  try {
    const store = getStore("sav-site-data");

    if (event.httpMethod === "GET") {
      const params = event.queryStringParameters || {};

      if (params.action === "list") {
        const prefix = params.prefix || "";
        const { blobs } = await store.list({ prefix });
        return {
          statusCode: 200,
          headers: CORS_HEADERS,
          body: JSON.stringify({ keys: blobs.map((b) => b.key) }),
        };
      }

      if (params.action === "get") {
        if (!params.key) {
          return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "key required" }) };
        }
        const value = await store.get(params.key);
        return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ value }) };
      }

      return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "unknown action" }) };
    }

    if (event.httpMethod === "POST") {
      const body = JSON.parse(event.body || "{}");

      if (body.action === "set") {
        if (!body.key) {
          return { statusCode: 400, headers: CORS_HEADERS, body: JSON.stringify({ error: "key required" }) };
        }
        await store.set(body.key, body.value ?? "");
        return { statusCode: 200, headers: CORS_HEADERS, body: JSON.stringify({ ok: true }) };
      }

      if (body.action === "delete") {
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
