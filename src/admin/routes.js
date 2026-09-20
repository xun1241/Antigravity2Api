const { parseJsonBody, extractApiKey, jsonResponse } = require("../utils/http");

const accounts = require("./accounts");
const oauth = require("./oauth");

function isApiKeyValid(apiKey, config) {
  const keys = Array.isArray(config?.api_keys) ? config.api_keys.filter(Boolean) : [];
  if (keys.length === 0) {
    return {
      ok: false,
      status: 503,
      message: "Admin API auth is not configured. Set AG2API_API_KEYS to enable admin endpoints.",
    };
  }
  if (!apiKey || !keys.includes(apiKey)) {
    return {
      ok: false,
      status: 401,
      message: "Invalid API Key",
    };
  }
  return { ok: true };
}

function logWarn(logger, message, meta) {
  if (!logger) return;
  if (typeof logger.log === "function") {
    logger.log("warn", message, meta);
    return;
  }
  if (typeof logger === "function") {
    logger("warn", message, meta);
  }
}

async function handleAdminRoute(req, parsedUrl, { authManager, upstreamClient, config, logger } = {}) {
  if (!parsedUrl.pathname.startsWith("/admin/api/")) return null;

  const apiKey = extractApiKey(req.headers);
  const auth = isApiKeyValid(apiKey, config);
  if (!auth.ok) {
    logWarn(logger, "⛔ Admin API unauthorized access", {
      ip: req.socket.remoteAddress,
      path: parsedUrl.pathname,
      status: auth.status,
    });
    return jsonResponse(auth.status, { error: { message: auth.message } });
  }

  try {
    if (parsedUrl.pathname === "/admin/api/accounts" && req.method === "GET") {
      return jsonResponse(200, { success: true, data: accounts.getAccountsPayload(authManager) });
    }

    if (parsedUrl.pathname === "/admin/api/accounts/reload" && req.method === "POST") {
      const data = await accounts.reloadAccounts(authManager);
      return jsonResponse(200, { success: true, data });
    }

    const quotaMatch = parsedUrl.pathname.match(/^\/admin\/api\/accounts\/(.+)\/quota$/);
    if (quotaMatch && req.method === "GET") {
      const fileName = decodeURIComponent(quotaMatch[1] || "");
      const data = await accounts.getAccountQuota(authManager, fileName, upstreamClient);
      return jsonResponse(200, { success: true, data });
    }

    const deleteMatch = parsedUrl.pathname.match(/^\/admin\/api\/accounts\/(.+)$/);
    if (deleteMatch && req.method === "DELETE") {
      const fileName = decodeURIComponent(deleteMatch[1] || "");
      const ok = await accounts.deleteAccount(authManager, fileName);
      if (!ok) {
        return jsonResponse(404, { success: false, message: "Account not found" });
      }
      return jsonResponse(200, { success: true, message: "Deleted" });
    }

    if (parsedUrl.pathname === "/admin/api/oauth/start" && req.method === "POST") {
      // Body reserved for future use; keep parsing to validate JSON.
      await parseJsonBody(req).catch((e) => {
        if (e?.message === "INVALID_JSON") throw e;
      });
      const data = oauth.startOAuthSession(req, config);
      return jsonResponse(200, { success: true, data });
    }

    if (parsedUrl.pathname === "/admin/api/oauth/complete" && req.method === "POST") {
      const body = await parseJsonBody(req);
      const data = await oauth.completeOAuthFromUserInput({ body: body || {}, authManager });
      return jsonResponse(200, { success: true, data });
    }

    const statusMatch = parsedUrl.pathname.match(/^\/admin\/api\/oauth\/status\/([^/]+)$/);
    if (statusMatch && req.method === "GET") {
      const state = decodeURIComponent(statusMatch[1] || "");
      const data = oauth.getOAuthStatus(state);
      return jsonResponse(200, { success: true, data });
    }

    return jsonResponse(404, { error: { message: `Not Found: ${req.method} ${req.url}` } });
  } catch (err) {
    if (err && err.message === "INVALID_JSON") {
      return jsonResponse(400, { error: { message: "Invalid JSON body" } });
    }
    return jsonResponse(500, { error: { message: err?.message || String(err) } });
  }
}

async function handleOAuthCallbackRoute(req, parsedUrl, { authManager } = {}) {
  if (parsedUrl.pathname !== "/oauth-callback" || req.method !== "GET") return null;

  const code = parsedUrl.searchParams.get("code");
  const state = parsedUrl.searchParams.get("state");
  const error = parsedUrl.searchParams.get("error");
  const errorDescription = parsedUrl.searchParams.get("error_description");

  const result = await oauth.completeOAuthCallback({
    state,
    code,
    error,
    errorDescription,
    authManager,
  });

  const html = oauth.renderOAuthResultPage({ ...result, state });
  return {
    status: result.success ? 200 : 400,
    headers: { "Content-Type": "text/html; charset=utf-8" },
    body: html,
  };
}

module.exports = {
  handleAdminRoute,
  handleOAuthCallbackRoute,
};
