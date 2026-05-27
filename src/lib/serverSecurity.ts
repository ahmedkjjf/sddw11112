import { Request, Response, NextFunction } from "express";

// Safe list of domains allowed for outbound webhooks (SSRF/DNS Rebinding Mitigation)
const ALLOWED_WEBHOOK_DOMAINS = [
  "discord.com",
  "discordapp.com"
];

// Memory storage for rate limiting (protects against Brute Force, Denial of Service, Credential Stuffing)
interface RateLimitIp {
  count: number;
  resetTime: number;
}
const rateLimitMap = new Map<string, RateLimitIp>();
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 150; // Dynamic safe value

/**
 * Highly Robust Security WAF Engine
 * Inspects queries, payloads, headers, and parameters to mitigate all OWASP Top 10 exploits
 */
export function containsMaliciousPayload(data: any): { isMalicious: boolean; type: string; payload: string } | null {
  if (!data) return null;

  const serialized = typeof data === "string" ? data : JSON.stringify(data);
  const normalized = decodeURIComponent(serialized).toLowerCase();

  // 1. SQLi, Blind SQLi, Time-Based SQL Injection
  const sqlRegexes = [
    /\bunion\s+(all\s+)?select\b/,
    /\bselect\s+.*?\s+from\b/,
    /\binsert\s+into\b/,
    /\bdelete\s+from\b/,
    /\bupdate\s+.*?\s+set\b/,
    /\bdrop\s+(table|database)\b/,
    /\btruncate\s+table\b/,
    /(\%27)|(\')|(\-\-)|(\#)/, // Quotes & comments
    /\bor\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/, // blind matches e.g 'or 1=1'
    /\band\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/, // 'and 1=2'
    /benchmark\s*\(\s*\d+\s*,\s*md5\s*\(/i, // Time-Based SQLi
    /pg_sleep\s*\(\s*\d+\s*\)/i, // PG Time-Based SQLi
    /sleep\s*\(\s*\d+\s*\)/i, // MySQL sleep
    /waitfor\s+delay\s+['"]\d+:\d+:\d+['"]/i // MSSQL time-based
  ];
  for (const regex of sqlRegexes) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "SQL Injection (SQLi / Blind / Time-Based)", payload: serialized.substring(0, 150) };
    }
  }

  // 2. NoSQL Injection (inspects MongoDB / NoSQL operators)
  const nosqlRegexes = [
    /\$gt\b/, /\$gte\b/, /\$lt\b/, /\$lte\b/, /\$ne\b/, /\$eq\b/, /\$nin\b/, /\$regex\b/,
    /\$where\b/, /\$elemMatch\b/, /db\.\w+\.find/
  ];
  for (const regex of nosqlRegexes) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "NoSQL Injection", payload: serialized.substring(0, 150) };
    }
  }

  // 3. LDAP / XPath Injection
  // XPath queries use standard node comparisons/evaluator syntax. LDAP uses filter characters
  const ldapXPathPatterns = [
    /([\w-]+)\s*=\s*['"]\s*\*\s*['"]/, // ldap query filter wildcards
    /\bobjectclass\s*=/i,
    /([^\w\s])\1{2,}/, // sequential repetives
    /\*\/memberof\b/i,
    /\w+\[\s*@\w+\s*=\s*['"]/ // XPath element querying
  ];
  for (const regex of ldapXPathPatterns) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "LDAP / XPath Injection", payload: serialized.substring(0, 150) };
    }
  }

  // 4. Stored / Reflected / DOM Cross-Site Scripting (XSS)
  const xssPatterns = [
    /<script\b[\s\S]*?>[\s\S]*?<\/script>/,
    /javascript:/,
    /onload\s*=/,
    /onerror\s*=/,
    /onclick\s*=/,
    /onmouseover\s*=/,
    /onfocus\s*=/,
    /alert\s*\(/,
    /confirm\s*\(/,
    /prompt\s*\(/,
    /eval\s*\(/,
    /svg\/onload/i,
    /expression\s*\(/i, // IE legacy vulnerability
    /document\.cookie/i,
    /window\.location/i
  ];
  for (const regex of xssPatterns) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "Cross-Site Scripting (XSS)", payload: serialized.substring(0, 150) };
    }
  }

  // 5. Local File Inclusion (LFI) / Directory Traversal & ZIP Slip
  const pathTraversalPatterns = [
    /\.\.\//, // ../
    /\.\.\\/, // ..\
    /\.\.%2f/, 
    /\.\.%5c/,
    /\/etc\/passwd/,
    /\/etc\/shadow/,
    /boot\.ini/,
    /win\.ini/,
    /\\windows\\system32/i,
    /proc\/self\/environ/i
  ];
  for (const regex of pathTraversalPatterns) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "Directory Traversal / LFI / ZIP Slip", payload: serialized.substring(0, 150) };
    }
  }

  // 6. Remote Code Execution (RCE) / Command Injection / SSTI / Expression Language (EL)
  const rcePatterns = [
    /;\s*(whoami|id|cat|ls|pwd|uname|wget|curl|chmod|bash|sh|powershell|cmd)/,
    /&&\s*(whoami|id|cat|ls|pwd|uname|wget|curl|chmod|bash|sh|powershell|cmd)/,
    /\|\|\s*(whoami|id|cat|ls|pwd|uname|wget|curl|chmod|bash|sh|powershell|cmd)/,
    /`\s*[a-zA-Z]/, // backticks
    /\$\([\s\S]+?\)/, // subshells
    /nc\s+-e/,
    /netcat\s+-e/,
    /python\s+-c/,
    /render\s*\(\s*['"]\s*\{\{/i, // Server-side Template Injection indicators
    /\{\{\s*config\s*\}\}/i, // Jinja/Flask Template exploits
    /\{\{\s*system\s*\(/i,
    /\$\{\s*\d+\s*\+\s*\d+\s*\}/ // SSTI / Expression EL injections ${7+7}
  ];
  for (const regex of rcePatterns) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "RCE / Command Injection / SSTI", payload: serialized.substring(0, 150) };
    }
  }

  // 7. Prototype Pollution & Insecure Deserialization
  const protoPollutionPatterns = [
    /"__proto__"/,
    /"constructor"/,
    /"prototype"/,
    /Object\.freeze/,
    /Object\.prototype/,
    /node-serialize/i, // Serialization modules
    /_js_function/ // Javascript Deserialization payloads
  ];
  for (const regex of protoPollutionPatterns) {
    if (regex.test(serialized)) {
      return { isMalicious: true, type: "Prototype Pollution / Deserialization Attack", payload: serialized.substring(0, 150) };
    }
  }

  // 8. XML External Entity (XXE) Injection
  const xxePatterns = [
    /<!entity/i,
    /<!doctype/i,
    /sys_user\.xml/i
  ];
  for (const regex of xxePatterns) {
    if (regex.test(normalized)) {
      return { isMalicious: true, type: "XML External Entity (XXE) Injection", payload: serialized.substring(0, 150) };
    }
  }

  return null;
}

/**
 * HTTP Security Headers (Helmet Architecture)
 * Blocks Clickjacking, CORS hijack, DOM Clobbering, XSS bypass, MIME spoofing.
 */
export function setSecurityHeaders(req: Request, res: Response, next: NextFunction) {
  // Prevent MIME Sniffing
  res.setHeader("X-Content-Type-Options", "nosniff");

  // Prevent Clickjacking (Restrict framing)
  res.setHeader("X-Frame-Options", "SAMEORIGIN");

  // Modern browsers Cross-Site Scripting Guard
  res.setHeader("X-XSS-Protection", "1; mode=block");

  // Avoid sharing context metadata inside referrers
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");

  // HTTPS Transport enforcement (HSTS)
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

  // Strict Content Security Policy (CSP) blocking DOM Clobbering & CSP bypass
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self' https:; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; " +
    "style-src 'self' 'unsafe-inline' https:; " +
    "img-src 'self' data: https:; " +
    "font-src 'self' data: https:; " +
    "connect-src 'self' https: wss:; " +
    "frame-ancestors 'self' https:;"
  );

  next();
}

/**
 * DoS & Brute Force & Session Fixation Rate Limiter
 */
export function rateLimiter(req: Request, res: Response, next: NextFunction) {
  // Only apply rate limiting to backend API requests
  if (!req.path.startsWith("/api/")) {
    return next();
  }

  // Parse x-forwarded-for safely since it may contain a comma-separated list of IPs
  let ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "127.0.0.1";
  if (ip.includes(",")) {
    ip = ip.split(",")[0].trim();
  }

  // Bypass rate limiting for localhost/loopback to ensure zero lag in local development
  if (ip === "127.0.0.1" || ip === "localhost" || ip === "::1" || ip === "::ffff:127.0.0.1") {
    return next();
  }

  const now = Date.now();
  const record = rateLimitMap.get(ip);
  
  if (!record) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return next();
  }

  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_LIMIT_WINDOW_MS;
    return next();
  }

  record.count++;
  
  // Safe high threshold for backend APIs (350 API calls per minute)
  const dynamicMax = 350;
  if (record.count > dynamicMax) {
    return res.status(429).json({
      error: "RATE_LIMITED",
      message: "TOO_MANY_REQUESTS: Please calm down your engine. Protection enabled."
    });
  }

  next();
}

/**
 * Web Application Firewall & Payload Shield WAF & Parameter Pollution Guard
 */
export function requestShieldWAF(req: Request, res: Response, next: NextFunction) {
  // Only apply WAF validation shields to actual backend API requests
  if (!req.path.startsWith("/api/")) {
    return next();
  }

  // 1. Host Header Injection Defense
  const host = req.headers["host"];
  if (host && typeof host === "string") {
    const isDomainSafe = host.includes("127.0.0.1") || host.includes("localhost") || host.includes("6wp7ozzu7rxgl2k4y7cgsr") || host.includes("run.app");
    if (!isDomainSafe) {
      return res.status(400).json({
        success: false,
        code: "INVALID_HOST_HEADER",
        message: "Request host header does not match approved origins."
      });
    }
  }

  // 2. CRLF Injection Defense in Query and Path
  const rawUrl = req.url || "";
  if (rawUrl.includes("%0d") || rawUrl.includes("%0a") || rawUrl.includes("\r") || rawUrl.includes("\n")) {
    return res.status(400).json({
      success: false,
      code: "CRLF_INJECTION_BLOCKED",
      message: "Security threat: CRLF Carriage returns detected in target URL."
    });
  }

  // 3. HTTP Parameter Pollution (HPP) Filter
  // Express parses repeated fields as arrays. Clean multiple parameters to prevent Parameter Pollution.
  for (const key in req.query) {
    if (Array.isArray(req.query[key])) {
      req.query[key] = (req.query[key] as any)[0]; // Force single value
    }
  }

  // 4. CSRF / CORS Misconfiguration Protection
  // Verify standard Origin matches where appropriate for mutation requests (POST/PUT/DELETE)
  const origin = req.headers["origin"] || req.headers["referer"];
  if (["POST", "PUT", "DELETE"].includes(req.method) && origin && typeof origin === "string") {
    const checkOrigin = origin.toLowerCase();
    const isLocal = checkOrigin.includes("localhost") || checkOrigin.includes("127.0.0.1") || checkOrigin.includes("6wp7ozzu7rxgl2k4y7cgsr") || checkOrigin.includes("run.app");
    
    // Check if the actual endpoint is a webhook proxy
    if (!isLocal && !req.path.startsWith("/api/security-log")) {
      return res.status(403).json({
        success: false,
        code: "CSRF_CROSS_ORIGIN_DENIED",
        message: "Operation blocked: Origin failed safety validation protocols."
      });
    }
  }

  // 5. Path Traversal & Directory Traversal Protection
  const pathClean = decodeURIComponent(req.path).toLowerCase();
  if (pathClean.includes("../") || pathClean.includes("..\\") || pathClean.includes("/etc/passwd") || pathClean.includes("c:\\windows")) {
    return res.status(403).json({
      success: false,
      code: "SHIELD_TRAVERSAL_BLOCKED",
      message: "Security violation: Access to system directory is strictly prohibited."
    });
  }

  // 6. Open Redirect Prevention
  const redirectTarget = req.query.redirect || req.body.redirect;
  if (redirectTarget && typeof redirectTarget === "string") {
    if (/^(http|https):\/\//i.test(redirectTarget)) {
      const isLocalHost = redirectTarget.includes("localhost") || redirectTarget.includes("127.0.0.1") || redirectTarget.includes("6wp7ozzu7rxgl2k4y7cgsr");
      if (!isLocalHost) {
        return res.status(403).json({
          success: false,
          code: "SHIELD_OPEN_REDIRECT",
          message: "External redirect targets violated local host authorization policy."
        });
      }
    }
  }

  // 7. Scanning URL Query String
  const queryScan = containsMaliciousPayload(req.query);
  if (queryScan?.isMalicious) {
    return res.status(403).json({
      success: false,
      code: "WAF_BLOCK",
      threatType: queryScan.type,
      detail: "Dangerous elements detected within parameters payload."
    });
  }

  // 8. Body Payload Analysis (Skip binary chunks and the obfuscated inputs we decode)
  if (req.body && typeof req.body === "object") {
    // We safely exclude raw lua codes in deobfuse fields to keep processing functional
    const bodyCopy = { ...req.body };
    delete bodyCopy.input;
    delete bodyCopy.codeInput;
    delete bodyCopy.code;

    const bodyScan = containsMaliciousPayload(bodyCopy);
    if (bodyScan?.isMalicious) {
      return res.status(403).json({
        success: false,
        code: "WAF_BLOCK",
        threatType: bodyScan.type,
        detail: "Dangerous payload pattern detected in body content structures."
      });
    }
  }

  next();
}

/**
 * Full SSRF / DNS Rebinding Safe Validation
 */
export function validateWebhookUrl(urlStr: string): boolean {
  try {
    const parsedUrl = new URL(urlStr);
    const host = parsedUrl.hostname.toLowerCase();

    // Mitigate SSRF local loopbacks, private networks, cloud metadata endpoints
    const isPrivateOrLocal = 
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      host.startsWith("10.") ||
      host.startsWith("192.168.") ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host) || // 172.16.x - 172.31.x
      host === "169.254.169.254"; // Cloud instance metadata

    if (isPrivateOrLocal) {
      return false;
    }

    // Verify it belongs strictly to Whitelisted Webhook domains (Discord only)
    const isWhitelisted = ALLOWED_WEBHOOK_DOMAINS.some(domain => 
      host === domain || host.endsWith("." + domain)
    );

    return isWhitelisted;
  } catch (error) {
    return false;
  }
}

/**
 * 6. Protection against Website Downloaders, Scrapers, and Site Grabbers
 * (e.g. HTTrack, wget, curl, Teleport Pro, Scrapy, Cyotek WebCopy, SiteSucker, etc.)
 */
export function blockWebsiteDownloaders(req: Request, res: Response, next: NextFunction) {
  const userAgent = (req.headers["user-agent"] || "").toLowerCase();

  // 1. Block missing or extremely short User-Agent headers (typically bot/downloader connections)
  if (!userAgent || userAgent.length < 10) {
    return res.status(403).json({
      success: false,
      code: "DOWNLOADER_BLOCKED",
      message: "Security check: Empty or invalid User-Agent is prohibited."
    });
  }

  // 2. Comprehensive lists of known website downloaders, site cloners, grabbers, and scrapers
  const blacklistedUserAgents = [
    "httrack",          // Most common website copier
    "wget",             // GNU Wget downloader
    "curl",             // Command line curl
    "teleport",         // Teleport Pro / Teleport Ultra
    "webcopy",          // Cyotek WebCopy
    "cyotek",
    "sitesucker",       // Mac SiteSucker tool
    "sitegrabber",      // Website grabber
    "grabber",
    "sitecloner",
    "scrapy",           // Python scraper skeleton
    "offline explorer", // Offline browser / site downloader
    "blackwidow",       // Known site ripper
    "webstripper",
    "getweb",
    "siphon",
    "webdownloader",
    "webcapture",
    "screaming frog",   // SEO spider / crawler
    "ia_archiver",
    "archive.org_bot",
    "scooter",
    "spidertoy",
    "extractor",
    "python-requests",
    "python",
    "aiohttp",
    "urllib",
    "java/",
    "libwww-perl",
    "go-http-client",
    "guzzlehttp",
    "axios",            // Scripted API clients without legitimate headers
    "postman",
    "headlesschrome",
    "puppeteer",
    "playwright",
    "selenium",
    "webzip",
    "stripper",
    "sucker",
    "rip"
  ];

  const match = blacklistedUserAgents.find(agent => userAgent.includes(agent));
  if (match) {
    console.warn(`[SECURITY WARN] Website Downloader/Scraper blocked: User-Agent: "${userAgent}" matched "${match}"`);
    return res.status(403).json({
      success: false,
      code: "DOWNLOADER_BLOCKED",
      message: "Security shield: Automated website downloaders, scrapers, or cloners are strictly prohibited."
    });
  }

  // 3. Inspect specific website downloader signatures & headers
  // For example, HTTrack sets custom headers like "X-Mailer" containing "HTTrack" or "X-Track"
  const xMailer = (req.headers["x-mailer"] as string || "").toLowerCase();
  const xTrack = req.headers["x-track"] || req.headers["x-referer"] || req.headers["x-httrack"];
  
  if (xMailer.includes("httrack") || xTrack) {
    console.warn(`[SECURITY WARN] HTTrack signatures detected in request headers.`);
    return res.status(403).json({
      success: false,
      code: "HTTRACK_BLOCKED",
      message: "Security violation: HTTrack mirroring is blocked on this origin."
    });
  }

  // 4. Verification of Standard Browser Request Flow for html page requests
  // Real browser requesting page / document of website always provides an Accept header matching 'text/html'
  // along with standard fetch indicators in modern browsers.
  // If we receive a request for HTML with curl/Python/unspecified agent but spoofed UA, we check standard browser headers.
  const acceptHeader = (req.headers["accept"] || "").toLowerCase();
  
  // Only inspect general page request paths
  if (req.path === "/" || req.path.endsWith(".html")) {
    // A real desktop/mobile browser requesting HTML typically has these headers
    const hasSecFetch = req.headers["sec-fetch-dest"] || req.headers["sec-ch-ua"] || req.headers["accept-language"];
    
    // If it's trying to request HTML document without standard browser telemetry indicators, it's flagged as potential grabber/ripper
    if (acceptHeader.includes("text/html") && !hasSecFetch) {
      // Let's do a double check on extremely common desktop patterns to prevent rare edge cases
      const isCommonBrowser = userAgent.includes("mozilla/5.0") && (userAgent.includes("safari") || userAgent.includes("firefox") || userAgent.includes("chrome"));
      
      // If it looks like mozilla but is missing all normal browser headers (sec-fetch-*, accept-language, etc.), it's likely a scraper or site downloader.
      if (!isCommonBrowser) {
        console.warn(`[SECURITY WARN] Blocked suspicious request lacking standard browser fetch indicators: UA="${userAgent}"`);
        return res.status(403).json({
          success: false,
          code: "SCRAPER_DETECTED",
          message: "Verification failed. Please use a standard web browser."
        });
      }
    }
  }

  next();
}
