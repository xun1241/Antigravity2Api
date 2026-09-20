const crypto = require("crypto");

const httpClient = require("../auth/httpClient");
const { escapeHtml } = require("../utils/html");

const SESSION_TTL_MS = 30 * 60 * 1000;
const sessions = new Map();

function nowMs() {
  return Date.now();
}

function hasUrlScheme(value) {
  return /^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(value);
}

function resolveServerPort(config) {
  const rawPort = config?.server?.port;
  if (typeof rawPort === "number" && Number.isFinite(rawPort)) return rawPort;
  if (typeof rawPort === "string" && rawPort.trim()) {
    const parsed = Number.parseInt(rawPort.trim(), 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return 3000;
}

function createState() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return crypto.randomBytes(16).toString("hex");
}

function parseOAuthInputToParams(input) {
  const raw = String(input || "").trim();
  if (!raw) return {};

  const candidates = [raw];
  if (!hasUrlScheme(raw)) {
    if (raw.startsWith("/")) candidates.push(`http://localhost${raw}`);
    if (raw.startsWith("?")) candidates.push(`http://localhost/oauth-callback${raw}`);
    if (/^localhost(:\d+)?\//i.test(raw)) candidates.push(`http://${raw}`);
    if (raw.includes("/oauth-callback")) candidates.push(`http://${raw.replace(/^\/+/, "")}`);
  }

  let params = null;
  for (const candidate of candidates) {
    try {
      const url = new URL(candidate);
      if (url && url.searchParams) {
        params = url.searchParams;
        break;
      }
    } catch (e) {}
  }

  if (!params && (raw.includes("code=") || raw.includes("state=") || raw.includes("error="))) {
    const q = raw.startsWith("?") ? raw.slice(1) : raw;
    try {
      params = new URLSearchParams(q);
    } catch (e) {}
  }

  if (!params) return { code: raw };

  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error");
  const errorDescription = params.get("error_description");

  if (!code && !state && !error) return { code: raw };
  return { code, state, error, errorDescription };
}

function cleanupExpiredSessions() {
  const now = nowMs();
  for (const [state, session] of sessions.entries()) {
    if (!session || !session.createdAt || now-session.createdAt > SESSION_TTL_MS) {
      sessions.delete(state);
    }
  }
}

function buildAuthUrl(state, redirectUri) {
  const { clientId } = httpClient.getOAuthClient();
  const scope = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/cclog",
    "https://www.googleapis.com/auth/experimentsandconfigs",
  ].join(" ");

  const params = new URLSearchParams({
    access_type: "offline",
    scope,
    state,
    prompt: "consent",
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
  });

  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

function startOAuthSession(req, config) {
  cleanupExpiredSessions();

  const port = resolveServerPort(config);
  const redirectUri = `http://localhost:${port}/oauth-callback`;

  const state = createState();
  const authUrl = buildAuthUrl(state, redirectUri);

  sessions.set(state, {
    createdAt: nowMs(),
    redirectUri,
    result: null,
  });

  return {
    state,
    auth_url: authUrl,
    redirect_uri: redirectUri,
    expires_in_ms: SESSION_TTL_MS,
  };
}

function getOAuthStatus(state) {
  cleanupExpiredSessions();
  const session = sessions.get(state);
  if (!session) {
    return { status: "expired", message: "OAuth state not found or expired" };
  }
  if (session.result) {
    return { status: "completed", ...session.result };
  }
  return { status: "pending" };
}

async function completeOAuthCallback({ state, code, error, errorDescription, authManager }) {
  cleanupExpiredSessions();

  if (!state) {
    return { success: false, message: "Missing state" };
  }

  const session = sessions.get(state);
  if (!session) {
    return { success: false, message: "OAuth state not found or expired" };
  }

  if (error) {
    const msg = `授权失败: ${errorDescription || error}`;
    const result = { success: false, message: msg };
    session.result = result;
    sessions.set(state, session);
    return result;
  }

  if (!code) {
    const result = { success: false, message: "Missing code" };
    session.result = result;
    sessions.set(state, session);
    return result;
  }

  try {
    const creds = await httpClient.exchangeCodeForToken(code, session.redirectUri, authManager.apiLimiter);
    await authManager.addAccount(creds);
    const result = { success: true, message: "授权成功" };
    session.result = result;
    sessions.set(state, session);
    return result;
  } catch (e) {
    const result = { success: false, message: `获取 token 失败: ${e.message || String(e)}` };
    session.result = result;
    sessions.set(state, session);
    return result;
  }
}

async function completeOAuthFromUserInput({ body, authManager }) {
  const rawState = typeof body?.state === "string" ? body.state.trim() : "";
  const rawCode = typeof body?.code === "string" ? body.code.trim() : "";
  const rawCallbackUrl = typeof body?.callback_url === "string" ? body.callback_url.trim() : "";

  const parsed = parseOAuthInputToParams(rawCallbackUrl);
  const state = rawState || parsed.state || "";
  const code = rawCode || parsed.code || "";

  const error = parsed.error;
  const errorDescription = parsed.errorDescription;

  if (!rawCallbackUrl && !rawCode) {
    return {
      success: false,
      message: "请输入回调链接（含 code/state）或授权码 code",
      state: state || rawState || "",
    };
  }

  if (!state) {
    return {
      success: false,
      message: "缺少 state：请先点击 “OAuth 添加账号” 生成 state，再粘贴回调链接或 code 提交",
      state: "",
    };
  }

  const result = await completeOAuthCallback({
    state,
    code,
    error,
    errorDescription,
    authManager,
  });

  return { ...result, state };
}

function renderOAuthResultPage({ success, message, state }) {
  const safeMessage = escapeHtml(message);
  const payload = {
    type: "oauth_result",
    state: state || "",
    success: !!success,
    message: message || "",
  };
  const payloadJson = JSON.stringify(payload).replaceAll("<", "\\u003c");

  const title = success ? "OAuth 授权成功" : "OAuth 授权失败";
  const statusClass = success ? "success" : "error";
  const statusText = success ? "成功" : "失败";

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0b1220; color: #e6edf3; margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .card { width: min(520px, 92vw); background: #111a2e; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 28px; box-shadow: 0 16px 40px rgba(0,0,0,0.5); }
    .badge { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 999px; font-weight: 600; font-size: 13px; letter-spacing: .2px; }
    .badge.success { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.35); }
    .badge.error { background: rgba(239, 68, 68, 0.12); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.35); }
    h1 { margin: 14px 0 10px; font-size: 22px; }
    p { margin: 0 0 14px; line-height: 1.6; color: rgba(230,237,243,0.85); }
    .hint { font-size: 13px; color: rgba(230,237,243,0.6); }
    .btn { margin-top: 18px; width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.12); background: rgba(255,255,255,0.06); color: #e6edf3; cursor: pointer; font-size: 14px; }
    .btn:hover { background: rgba(255,255,255,0.10); }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge ${statusClass}">OAuth ${statusText}</div>
    <h1>${title}</h1>
    <p>${safeMessage}</p>
    <p class="hint" id="countdown">窗口将在 3 秒后自动关闭</p>
    <button class="btn" onclick="closeWindow()">关闭窗口</button>
  </div>
  <script>
    const payload = ${payloadJson};

    try {
      if (window.opener && !window.opener.closed) {
        window.opener.postMessage(payload, window.location.origin);
      }
    } catch (e) {}

    function closeWindow() {
      window.close();
      setTimeout(() => {
        if (!window.closed) {
          document.getElementById('countdown').textContent = '请手动关闭此窗口';
        }
      }, 100);
    }

    let t = 3;
    const el = document.getElementById('countdown');
    const timer = setInterval(() => {
      t -= 1;
      if (t > 0) {
        el.textContent = '窗口将在 ' + t + ' 秒后自动关闭';
      } else {
        clearInterval(timer);
        closeWindow();
      }
    }, 1000);
  </script>
</body>
</html>`;
}

module.exports = {
  startOAuthSession,
  getOAuthStatus,
  completeOAuthCallback,
  completeOAuthFromUserInput,
  renderOAuthResultPage,
};
