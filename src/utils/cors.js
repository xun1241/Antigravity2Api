const DEFAULT_CORS_ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000"];
const ALLOW_METHODS = "GET, POST, DELETE, OPTIONS";
const ALLOW_HEADERS = "Content-Type, Authorization, x-api-key, anthropic-api-key, x-goog-api-key, anthropic-version";

function parseCorsOrigins(value) {
  if (Array.isArray(value)) {
    return value.map((v) => String(v || "").trim()).filter(Boolean);
  }
  if (typeof value !== "string") return null;
  const raw = value.trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((v) => String(v || "").trim())
    .filter(Boolean);
}

function isOriginAllowed(origin, corsOrigins) {
  if (!origin || typeof origin !== "string") return false;
  const allowed = Array.isArray(corsOrigins) ? corsOrigins : [];
  return allowed.includes(origin);
}

function getCorsHeaders({ origin, corsOrigins, preflight = false } = {}) {
  if (!origin || !isOriginAllowed(origin, corsOrigins)) return {};
  const headers = {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
  };
  if (preflight) {
    headers["Access-Control-Allow-Methods"] = ALLOW_METHODS;
    headers["Access-Control-Allow-Headers"] = ALLOW_HEADERS;
  }
  return headers;
}

module.exports = {
  DEFAULT_CORS_ORIGINS,
  parseCorsOrigins,
  isOriginAllowed,
  getCorsHeaders,
};
