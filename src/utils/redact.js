const SENSITIVE_KEY_REGEX =
  /^(authorization|proxy-authorization|x-api-key|anthropic-api-key|x-goog-api-key|cookie|set-cookie|access_token|refresh_token|id_token|client_secret|token|api[_-]?key|secret|password|code)$/i;

function isSensitiveKey(key) {
  return SENSITIVE_KEY_REGEX.test(String(key || "").trim());
}

function truncateText(value, maxLen) {
  const text = String(value || "");
  if (text.length <= maxLen) return text;
  return `${text.slice(0, maxLen)}... [truncated ${text.length - maxLen} chars]`;
}

function redactString(value, options = {}) {
  const maxStringLength = options.maxStringLength ?? 1200;
  let text = String(value || "");

  text = text.replace(/(Bearer\s+)[A-Za-z0-9\-._~+/]+=*/gi, "$1[REDACTED]");
  text = text.replace(
    /([?&](?:access_token|refresh_token|id_token|client_secret|code)=)[^&#\s]*/gi,
    "$1[REDACTED]"
  );
  text = text.replace(
    /((?:access_token|refresh_token|id_token|client_secret|authorization|x-api-key|anthropic-api-key|x-goog-api-key|cookie|set-cookie|code)\s*[=:]\s*)([^\s,;]+)/gi,
    "$1[REDACTED]"
  );

  return truncateText(text, maxStringLength);
}

function redactForLog(value, options = {}, ctx = {}) {
  const {
    maxDepth = 4,
    maxArrayLength = 20,
    maxObjectKeys = 50,
  } = options;
  const seen = ctx.seen || new WeakSet();
  const depth = ctx.depth || 0;

  if (value == null) return value;
  if (typeof value === "string") return redactString(value, options);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "function") return "[Function]";
  if (Buffer.isBuffer(value)) return `[Buffer ${value.length} bytes]`;
  if (value instanceof Error) {
    return {
      name: value.name,
      message: redactString(value.message || "", options),
      stack: redactString(value.stack || "", options),
    };
  }

  if (depth >= maxDepth) return "[Truncated depth]";

  if (Array.isArray(value)) {
    const out = value.slice(0, maxArrayLength).map((item) =>
      redactForLog(item, options, { seen, depth: depth + 1 })
    );
    if (value.length > maxArrayLength) {
      out.push(`[Truncated ${value.length - maxArrayLength} items]`);
    }
    return out;
  }

  if (typeof value === "object") {
    if (seen.has(value)) return "[Circular]";
    seen.add(value);

    const out = {};
    const keys = Object.keys(value);
    const limitedKeys = keys.slice(0, maxObjectKeys);
    for (const key of limitedKeys) {
      if (isSensitiveKey(key)) {
        out[key] = "[REDACTED]";
      } else {
        out[key] = redactForLog(value[key], options, { seen, depth: depth + 1 });
      }
    }
    if (keys.length > maxObjectKeys) {
      out.__truncated_keys__ = keys.length - maxObjectKeys;
    }
    return out;
  }

  return redactString(String(value), options);
}

module.exports = {
  isSensitiveKey,
  redactString,
  redactForLog,
};
