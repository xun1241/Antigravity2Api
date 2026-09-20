const assert = require("assert");

const { handleAdminRoute } = require("./src/admin/routes");
const { getCorsHeaders } = require("./src/utils/cors");
const { renderOAuthResultPage } = require("./src/admin/oauth");
const OAuthFlow = require("./src/auth/OAuthFlow");
const { redactForLog, redactString } = require("./src/utils/redact");

async function testAdminApiFailsClosedWithoutKeys() {
  const req = { method: "GET", url: "/admin/api/accounts", headers: {}, socket: { remoteAddress: "127.0.0.1" } };
  const parsedUrl = new URL("http://localhost/admin/api/accounts");
  const resp = await handleAdminRoute(req, parsedUrl, {
    config: { api_keys: [] },
    authManager: {},
    upstreamClient: {},
  });
  assert(resp, "expected admin route response");
  assert.strictEqual(resp.status, 503);
  assert.match(resp.body.error.message, /not configured/i);
}

async function testAdminApiAcceptsConfiguredKey() {
  const req = {
    method: "GET",
    url: "/admin/api/accounts",
    headers: { "x-api-key": "k1" },
    socket: { remoteAddress: "127.0.0.1" },
  };
  const parsedUrl = new URL("http://localhost/admin/api/accounts");
  const authManager = {
    getAccountsSummary: () => [],
    getCurrentAccountIndex: () => 0,
  };
  const resp = await handleAdminRoute(req, parsedUrl, {
    config: { api_keys: ["k1"] },
    authManager,
    upstreamClient: {},
  });
  assert(resp, "expected admin route response");
  assert.strictEqual(resp.status, 200);
}

function testCorsAllowlist() {
  const allow = getCorsHeaders({
    origin: "http://localhost:3000",
    corsOrigins: ["http://localhost:3000"],
    preflight: true,
  });
  assert.strictEqual(allow["Access-Control-Allow-Origin"], "http://localhost:3000");
  assert.strictEqual(allow.Vary, "Origin");
  assert(allow["Access-Control-Allow-Methods"]);

  const deny = getCorsHeaders({
    origin: "https://evil.example",
    corsOrigins: ["http://localhost:3000"],
    preflight: true,
  });
  assert.deepStrictEqual(deny, {});
}

function testOAuthHtmlEscapingInResultPage() {
  const payload = `<img src=x onerror=alert("xss")>`;
  const html = renderOAuthResultPage({ success: false, message: payload, state: "s1" });
  assert(html.includes("&lt;img src=x onerror=alert(&quot;xss&quot;)&gt;"));
  assert(!html.includes(payload));
}

async function testOAuthFlowEscaping() {
  const flow = new OAuthFlow({
    authManager: { addAccount: async () => {} },
  });
  flow.exchangeCode = async () => {
    throw new Error(`token failed <img src=x onerror=alert('xss')>`);
  };

  const { server, port } = await flow.startCallbackServer(56000, 56200, false);
  try {
    const payload = `<script>alert("xss")</script>`;
    const errorRes = await fetch(
      `http://localhost:${port}/oauth-callback?error=access_denied&error_description=${encodeURIComponent(payload)}`
    );
    const errorHtml = await errorRes.text();
    assert(errorHtml.includes("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"));
    assert(!errorHtml.includes(payload));

    const tokenRes = await fetch(`http://localhost:${port}/oauth-callback?code=fake-code`);
    const tokenHtml = await tokenRes.text();
    assert(tokenHtml.includes("&lt;img src=x onerror=alert(&#39;xss&#39;)&gt;"));
    assert(!tokenHtml.includes("<img src=x onerror=alert('xss')>"));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function testRedaction() {
  const redacted = redactForLog({
    authorization: "******",
    nested: {
      refresh_token: "r1",
      text: "access_token=abc&code=xyz",
    },
  });
  assert.strictEqual(redacted.authorization, "[REDACTED]");
  assert.strictEqual(redacted.nested.refresh_token, "[REDACTED]");
  assert.match(redacted.nested.text, /\[REDACTED\]/);

  const redactedString = redactString("Authorization: ******");
  assert.match(redactedString, /\[REDACTED\]/);
}

async function main() {
  await testAdminApiFailsClosedWithoutKeys();
  await testAdminApiAcceptsConfiguredKey();
  testCorsAllowlist();
  testOAuthHtmlEscapingInResultPage();
  await testOAuthFlowEscaping();
  testRedaction();
  console.log("✅ test_security_hardening: PASS");
}

main().catch((err) => {
  console.error("❌ test_security_hardening: FAIL\n", err);
  process.exitCode = 1;
});
