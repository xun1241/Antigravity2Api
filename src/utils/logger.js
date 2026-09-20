const fs = require("fs");
const path = require("path");
const { redactForLog, redactString } = require("./redact");

// ANSI 颜色代码
const Colors = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  
  // 前景色
  black: "\x1b[30m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
  
  // 亮色
  brightRed: "\x1b[91m",
  brightGreen: "\x1b[92m",
  brightYellow: "\x1b[93m",
  brightBlue: "\x1b[94m",
  brightMagenta: "\x1b[95m",
  brightCyan: "\x1b[96m",
  
  // 背景色
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
  bgBlue: "\x1b[44m",
  bgMagenta: "\x1b[45m",
  bgCyan: "\x1b[46m",
};

// 日志级别配置
const LogLevels = {
  debug: { priority: 0, icon: "🔍", color: Colors.gray, label: "DEBUG" },
  info: { priority: 1, icon: "ℹ️ ", color: Colors.cyan, label: "INFO" },
  success: { priority: 1, icon: "✅", color: Colors.green, label: "SUCCESS" },
  warn: { priority: 2, icon: "⚠️ ", color: Colors.yellow, label: "WARN" },
  error: { priority: 3, icon: "❌", color: Colors.red, label: "ERROR" },
  fatal: { priority: 4, icon: "💀", color: Colors.brightRed, label: "FATAL" },
  
  // 特殊日志类型
  request: { priority: 1, icon: "📤", color: Colors.blue, label: "REQUEST" },
  response: { priority: 1, icon: "📥", color: Colors.green, label: "RESPONSE" },
  upstream: { priority: 1, icon: "🔗", color: Colors.magenta, label: "UPSTREAM" },
  retry: { priority: 2, icon: "🔄", color: Colors.yellow, label: "RETRY" },
  account: { priority: 1, icon: "👤", color: Colors.cyan, label: "ACCOUNT" },
  quota: { priority: 2, icon: "📊", color: Colors.yellow, label: "QUOTA" },
  stream: { priority: 0, icon: "📡", color: Colors.gray, label: "STREAM" },
};

// 边框字符
const Box = {
  topLeft: "┌",
  topRight: "┐",
  bottomLeft: "└",
  bottomRight: "┘",
  horizontal: "─",
  vertical: "│",
  teeRight: "├",
  teeLeft: "┤",
};

function ensureDir(dirPath) {
  if (fs.existsSync(dirPath)) return;
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (err) {
    console.error("Failed to create log directory:", err);
  }
}

function normalizeRetentionDays(value, fallbackDays) {
  if (value === undefined || value === null || value === "") return fallbackDays;
  const n = Number.parseInt(String(value).trim(), 10);
  if (!Number.isFinite(n) || n < 0) return fallbackDays;
  return n;
}

async function cleanupOldLogs(logDir, retentionDays) {
  if (!Number.isFinite(retentionDays) || retentionDays <= 0) return { deleted: 0, scanned: 0 };

  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  let entries = [];
  try {
    entries = await fs.promises.readdir(logDir, { withFileTypes: true });
  } catch {
    return { deleted: 0, scanned: 0 };
  }

  let scanned = 0;
  let deleted = 0;

  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!entry.name.endsWith(".log")) continue;
    scanned++;

    const filePath = path.join(logDir, entry.name);
    try {
      const stat = await fs.promises.stat(filePath);
      if (stat.mtimeMs >= cutoffMs) continue;
      await fs.promises.unlink(filePath);
      deleted++;
    } catch {
      // ignore (locked file / permission / race)
    }
  }

  return { deleted, scanned };
}

function formatTimestamp() {
  const now = new Date();
  const hours = String(now.getHours()).padStart(2, "0");
  const minutes = String(now.getMinutes()).padStart(2, "0");
  const seconds = String(now.getSeconds()).padStart(2, "0");
  const ms = String(now.getMilliseconds()).padStart(3, "0");
  return `${hours}:${minutes}:${seconds}.${ms}`;
}

function formatFullTimestamp() {
  return new Date().toISOString();
}

function formatDuration(ms) {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(1);
  return `${minutes}m ${seconds}s`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)}MB`;
}

function truncateString(str, maxLen = 200) {
  if (!str || str.length <= maxLen) return str;
  return str.substring(0, maxLen) + `... (${str.length - maxLen} more chars)`;
}

function formatLogContent(data, options = {}) {
  const { indent = 2, maxDepth = 4, compact = false } = options;
  
  if (typeof data === "string") {
    try {
      const parsed = JSON.parse(data);
      return JSON.stringify(parsed, null, compact ? 0 : indent);
    } catch (e) {
      return data;
    }
  }
  if (data !== undefined && data !== null) {
    try {
      return JSON.stringify(data, null, compact ? 0 : indent);
    } catch (e) {
      return String(data);
    }
  }
  return "";
}

function createBoxedMessage(title, content, options = {}) {
  const { width = 80, color = Colors.cyan } = options;
  const lines = [];
  
  const titleLine = ` ${title} `;
  const paddingLen = Math.max(0, width - titleLine.length - 2);
  const leftPad = Math.floor(paddingLen / 2);
  const rightPad = paddingLen - leftPad;
  
  lines.push(
    `${color}${Box.topLeft}${Box.horizontal.repeat(leftPad)}${Colors.bold}${titleLine}${Colors.reset}${color}${Box.horizontal.repeat(rightPad)}${Box.topRight}${Colors.reset}`
  );
  
  if (content) {
    const contentLines = content.split("\n");
    for (const line of contentLines) {
      const truncated = line.length > width - 4 ? line.substring(0, width - 7) + "..." : line;
      const padRight = Math.max(0, width - truncated.length - 4);
      lines.push(`${color}${Box.vertical}${Colors.reset} ${truncated}${" ".repeat(padRight)} ${color}${Box.vertical}${Colors.reset}`);
    }
  }
  
  lines.push(`${color}${Box.bottomLeft}${Box.horizontal.repeat(width - 2)}${Box.bottomRight}${Colors.reset}`);
  
  return lines.join("\n");
}

function createSeparator(char = "─", length = 60, color = Colors.gray) {
  return `${color}${char.repeat(length)}${Colors.reset}`;
}

/**
 * 创建增强的日志记录器
 */
function createLogger(options = {}) {
  const logDir = options.logDir || path.resolve(process.cwd(), "log");
  ensureDir(logDir);

  const retentionDays = normalizeRetentionDays(
    options.retentionDays ?? options.logRetentionDays ?? options.retention_days,
    3
  );

  const now = new Date();
  const logFileName = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(
    now.getDate()
  ).padStart(2, "0")}_${String(now.getHours()).padStart(2, "0")}-${String(now.getMinutes()).padStart(
    2,
    "0"
  )}-${String(now.getSeconds()).padStart(2, "0")}.log`;

  const logFile = path.join(logDir, logFileName);
  
  const minLevel = options.minLevel || "debug";
  const minPriority = (LogLevels[minLevel] || LogLevels.debug).priority;
  const logBodies = !!(options.logBodies ?? options.debug ?? false);

  // 请求计数器和统计
  const stats = {
    requests: 0,
    responses: 0,
    errors: 0,
    retries: 0,
    upstreamCalls: 0,
    startTime: Date.now(),
  };

  console.log(`${Colors.cyan}${Box.topLeft}${Box.horizontal.repeat(58)}${Box.topRight}${Colors.reset}`);
  console.log(`${Colors.cyan}${Box.vertical}${Colors.reset}  ${Colors.bold}📝 日志系统初始化${Colors.reset}${" ".repeat(39)}${Colors.cyan}${Box.vertical}${Colors.reset}`);
  console.log(`${Colors.cyan}${Box.vertical}${Colors.reset}  ${Colors.gray}文件: ${logFile}${Colors.reset}${" ".repeat(Math.max(0, 56 - 7 - logFile.length))}${Colors.cyan}${Box.vertical}${Colors.reset}`);
  console.log(`${Colors.cyan}${Box.bottomLeft}${Box.horizontal.repeat(58)}${Box.bottomRight}${Colors.reset}`);

  // 日志清理
  if (retentionDays > 0) {
    cleanupOldLogs(logDir, retentionDays)
      .then(({ deleted }) => {
        if (deleted > 0) {
          console.log(`${Colors.gray}[${formatTimestamp()}]${Colors.reset} ${Colors.yellow}🧹${Colors.reset} 已清理 ${Colors.bold}${deleted}${Colors.reset} 个过期日志文件 (保留 ${retentionDays} 天)`);
        }
      })
      .catch(() => {});

    const intervalMs = options.cleanupIntervalMs ?? 12 * 60 * 60 * 1000;
    const timer = setInterval(() => {
      cleanupOldLogs(logDir, retentionDays).catch(() => {});
    }, intervalMs);
    if (typeof timer.unref === "function") timer.unref();
  }

  /**
   * 核心日志函数
   * @param {string} level - 日志级别
   * @param {string} message - 日志消息
   * @param {object} [meta] - 附加元数据
   */
  const log = (level, message, meta = null) => {
    const levelConfig = LogLevels[level] || LogLevels.info;
    
    // 过滤低优先级日志
    if (levelConfig.priority < minPriority) return;
    
    const timestamp = formatTimestamp();
    const fullTimestamp = formatFullTimestamp();
    
    // 更新统计
    if (level === "request") stats.requests++;
    if (level === "response") stats.responses++;
    if (level === "error" || level === "fatal") stats.errors++;
    if (level === "retry") stats.retries++;
    if (level === "upstream") stats.upstreamCalls++;
    
    // 控制台输出（带颜色）
    const icon = levelConfig.icon;
    const coloredLevel = `${levelConfig.color}${levelConfig.label.padEnd(8)}${Colors.reset}`;
    const timeStr = `${Colors.gray}[${timestamp}]${Colors.reset}`;
    
    const safeMessage = redactString(message, { maxStringLength: 1500 });
    const safeMeta = meta !== null && meta !== undefined ? redactForLog(meta) : meta;

    let consoleOutput = `${timeStr} ${icon} ${coloredLevel} ${safeMessage}`;
    
    // 如果有元数据，格式化输出
    if (safeMeta !== null && safeMeta !== undefined) {
      const metaStr = formatLogContent(safeMeta);
      if (metaStr) {
        // 多行数据使用缩进显示
        if (metaStr.includes("\n")) {
          const indentedMeta = metaStr.split("\n").map(line => `   ${Colors.dim}│${Colors.reset} ${line}`).join("\n");
          consoleOutput += `\n${indentedMeta}`;
        } else {
          consoleOutput += ` ${Colors.dim}→${Colors.reset} ${Colors.gray}${truncateString(metaStr, 100)}${Colors.reset}`;
        }
      }
    }
    
    console.log(consoleOutput);
    
    // 文件日志（纯文本，无颜色）
    const separator = "-".repeat(60);
    const metaContent = safeMeta !== null && safeMeta !== undefined ? formatLogContent(safeMeta) : "";
    const fileEntry = `[${fullTimestamp}] [${levelConfig.label}] ${safeMessage}\n${metaContent ? metaContent + "\n" : ""}${separator}\n`;
    
    fs.appendFile(logFile, fileEntry, (err) => {
      if (err) console.error("Failed to write to log file:", err);
    });
  };

  /**
   * 记录 HTTP 请求
   */
  const logRequest = (method, url, options = {}) => {
    const { headers, body, requestId } = options;
    const reqIdStr = requestId ? ` ${Colors.dim}[${requestId}]${Colors.reset}` : "";
    
    console.log(`\n${createSeparator("═", 70, Colors.blue)}`);
    log("request", `${Colors.bold}${method}${Colors.reset} ${url}${reqIdStr}`);
    
    if (headers && Object.keys(headers).length > 0) {
      log("debug", "请求头", headers);
    }
    
    if (body && logBodies) {
      log("debug", "请求体", body);
    }
    
    return { startTime: Date.now(), requestId };
  };

  /**
   * 记录 HTTP 响应
   */
  const logResponse = (status, options = {}) => {
    const { duration, size, requestId, headers, body } = options;
    const reqIdStr = requestId ? ` ${Colors.dim}[${requestId}]${Colors.reset}` : "";
    
    const statusColor = status >= 500 ? Colors.red : status >= 400 ? Colors.yellow : Colors.green;
    const statusIcon = status >= 500 ? "❌" : status >= 400 ? "⚠️" : "✅";
    
    let metaInfo = [];
    if (duration) metaInfo.push(`⏱️  ${formatDuration(duration)}`);
    if (size) metaInfo.push(`📦 ${formatBytes(size)}`);
    
    log("response", `${statusIcon} ${statusColor}${Colors.bold}${status}${Colors.reset}${reqIdStr} ${Colors.dim}${metaInfo.join(" | ")}${Colors.reset}`);
    
    if (headers) {
      log("debug", "响应头", headers);
    }
    
    if (body && logBodies) {
      log("debug", "响应体", body);
    }
    
    console.log(`${createSeparator("═", 70, Colors.green)}\n`);
  };

  /**
   * 记录上游 API 调用
   */
  const logUpstream = (action, options = {}) => {
    const { method, account, model, group, attempt, maxAttempts, status, duration, error } = options;
    
    const attemptStr = attempt && maxAttempts ? `[${attempt}/${maxAttempts}]` : "";
    const accountStr = account ? `${Colors.cyan}@${account}${Colors.reset}` : "";
    const modelStr = model ? `${Colors.magenta}${model}${Colors.reset}` : "";
    const groupStr = group ? `[${group}]` : "";
    
    let message = `${action} ${attemptStr} ${groupStr} ${accountStr} ${modelStr}`.trim();
    
    if (status) {
      const statusColor = status >= 500 ? Colors.red : status >= 400 ? Colors.yellow : Colors.green;
      message += ` → ${statusColor}${status}${Colors.reset}`;
    }
    
    if (duration) {
      message += ` ${Colors.dim}(${formatDuration(duration)})${Colors.reset}`;
    }
    
    if (error) {
      log("upstream", message, { error });
    } else {
      log("upstream", message);
    }
  };

  /**
   * 记录重试事件
   */
  const logRetry = (reason, options = {}) => {
    const { attempt, maxAttempts, delayMs, account, error, nextAction } = options;
    
    const attemptStr = attempt && maxAttempts ? `[${attempt}/${maxAttempts}]` : "";
    const delayStr = delayMs ? `延迟 ${formatDuration(delayMs)}` : "";
    const accountStr = account ? `账户: ${account}` : "";
    const nextStr = nextAction ? `→ ${nextAction}` : "";
    
    let message = `${reason} ${attemptStr}`;
    const details = [delayStr, accountStr, nextStr].filter(Boolean).join(" | ");
    if (details) message += ` ${Colors.dim}(${details})${Colors.reset}`;
    
    if (error) {
      log("retry", message, { error });
    } else {
      log("retry", message);
    }
  };

  /**
   * 记录配额/限流事件
   */
  const logQuota = (event, options = {}) => {
    const { account, group, resetDelay, remaining, limit } = options;
    
    const accountStr = account ? `${Colors.cyan}@${account}${Colors.reset}` : "";
    const groupStr = group ? `[${group}]` : "";
    const resetStr = resetDelay ? `重置: ${formatDuration(resetDelay)}` : "";
    const quotaStr = remaining !== undefined && limit ? `${remaining}/${limit}` : "";
    
    let message = `${event} ${groupStr} ${accountStr}`.trim();
    const details = [resetStr, quotaStr].filter(Boolean).join(" | ");
    if (details) message += ` ${Colors.dim}(${details})${Colors.reset}`;
    
    log("quota", message);
  };

  /**
   * 记录账户事件
   */
  const logAccount = (action, options = {}) => {
    const { email, account, group, reason } = options;
    
    const emailStr = email ? `${Colors.cyan}${email}${Colors.reset}` : "";
    const accountStr = account ? `${Colors.cyan}@${account}${Colors.reset}` : "";
    const groupStr = group ? `[${group}]` : "";
    const reasonStr = reason ? `${Colors.dim}(${reason})${Colors.reset}` : "";
    
    const message = `${action} ${groupStr} ${emailStr || accountStr} ${reasonStr}`.trim();
    log("account", message);
  };

  /**
   * 记录流式传输事件
   */
  const logStream = (event, options = {}) => {
    const { chunks, bytes, duration, error } = options;
    
    let message = event;
    const details = [];
    if (chunks) details.push(`${chunks} chunks`);
    if (bytes) details.push(formatBytes(bytes));
    if (duration) details.push(formatDuration(duration));
    
    if (details.length > 0) {
      message += ` ${Colors.dim}(${details.join(" | ")})${Colors.reset}`;
    }
    
    if (error) {
      log("stream", message, { error });
    } else {
      log("stream", message);
    }
  };

  /**
   * 记录错误（带堆栈）
   */
  const logError = (message, error, options = {}) => {
    const { context, requestId } = options;
    const reqIdStr = requestId ? ` [${requestId}]` : "";
    
    console.log(`\n${Colors.red}${Box.topLeft}${Box.horizontal.repeat(68)}${Box.topRight}${Colors.reset}`);
    
    const errorMessage = error?.message || String(error);
    log("error", `${message}${reqIdStr}`, { 
      message: errorMessage,
      ...(error?.stack ? { stack: error.stack } : {}),
      ...(context || {})
    });
    
    console.log(`${Colors.red}${Box.bottomLeft}${Box.horizontal.repeat(68)}${Box.bottomRight}${Colors.reset}\n`);
  };

  /**
   * 获取运行统计
   */
  const getStats = () => {
    return {
      ...stats,
      uptime: Date.now() - stats.startTime,
      uptimeFormatted: formatDuration(Date.now() - stats.startTime),
    };
  };

  /**
   * 打印统计摘要
   */
  const logStats = () => {
    const s = getStats();
    console.log(`\n${createSeparator("═", 60, Colors.cyan)}`);
    console.log(`${Colors.bold}📊 运行统计${Colors.reset}`);
    console.log(`${Colors.dim}├${Colors.reset} 运行时长: ${s.uptimeFormatted}`);
    console.log(`${Colors.dim}├${Colors.reset} 请求总数: ${s.requests}`);
    console.log(`${Colors.dim}├${Colors.reset} 响应总数: ${s.responses}`);
    console.log(`${Colors.dim}├${Colors.reset} 上游调用: ${s.upstreamCalls}`);
    console.log(`${Colors.dim}├${Colors.reset} 重试次数: ${s.retries}`);
    console.log(`${Colors.dim}└${Colors.reset} 错误次数: ${s.errors}`);
    console.log(`${createSeparator("═", 60, Colors.cyan)}\n`);
  };

  return { 
    log, 
    logFile,
    logRequest,
    logResponse,
    logUpstream,
    logRetry,
    logQuota,
    logAccount,
    logStream,
    logError,
    getStats,
    logStats,
    // 便捷方法
    debug: (msg, meta) => log("debug", msg, meta),
    info: (msg, meta) => log("info", msg, meta),
    success: (msg, meta) => log("success", msg, meta),
    warn: (msg, meta) => log("warn", msg, meta),
    error: (msg, meta) => log("error", msg, meta),
    // 辅助工具
    formatDuration,
    formatBytes,
    Colors,
    Box,
  };
}

module.exports = {
  createLogger,
  Colors,
  LogLevels,
  Box,
};
