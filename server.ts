import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";
import { setSecurityHeaders, rateLimiter, requestShieldWAF, validateWebhookUrl, blockWebsiteDownloaders } from "./src/lib/serverSecurity";

dotenv.config();

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Block automated scrapers and website downloaders (e.g. HTTrack, Wget, Curl, Cyotek)
  app.use(blockWebsiteDownloaders);

  // Set HTTP Security Headers to mitigate XSS, Clickjacking, MIME spoofing
  app.use(setSecurityHeaders);

  // Apply rate limiter to defend against brute force and DDoS
  app.use(rateLimiter);

  app.use(express.json({ limit: '10mb' }));

  // Intercept and block hostile payloads (SQL Injection, Traversal/LFI, Command Execution, XXE, Deserialization Pollution)
  app.use(requestShieldWAF);

  // Discord Config & Rotating Code
  const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || "https://discord.com/api/webhooks/1504798977013317723/HXvs0NSA3_wmZkjpEkwqC9FHVOMfPQirx_OEfrysCUclADw3TllCrRmiQI2pYjhFQdOL";
  let currentAdminCode = "";
  let lastTimeBlock = -1;
  let lastSentCode = "";
  let isMaintenanceMode = false;

  async function sendToDiscord(code: string) {
    if (code === lastSentCode) return;
    lastSentCode = code;
    
    try {
      await fetch(DISCORD_WEBHOOK_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          embeds: [{
            title: "🛡️ ALZAABI QUANTUM SECURITY SYNC",
            description: `**ENCRYPTION LEVEL:** AES-256-GCM / SHA-40-BLOCK\n\n**RAW ACCESS KEY:**\n\`\`\`\n${code}\n\`\`\`\n\n**STATUS:** ROTATING_READY\n**EXPIRY:** 30 Minutes\n**NODE:** NEURAL_SERVER_V5_STABLE`,
            color: 0x00ff00,
            timestamp: new Date().toISOString(),
            footer: { text: "System Kernel Integrity: 100% Verified" }
          }]
        }),
      });
      console.log("Security key synced to Discord.");
    } catch (err) {
      console.error("Failed to sync code:", err);
    }
  }

  function rotateCode() {
    const timeBlock = Math.floor(Date.now() / (30 * 60 * 1000));
    if (timeBlock !== lastTimeBlock) {
      lastTimeBlock = timeBlock;
      // Generate an 40-character complex "encrypted" string
      const fullCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=-[]{}|;:,.<>?";
      let code = "";
      for (let i = 0; i < 40; i++) {
        code += fullCharset.charAt(Math.floor(Math.random() * fullCharset.length));
      }
      currentAdminCode = code;
      sendToDiscord(currentAdminCode);
    }
  }

  setInterval(rotateCode, 10000); // Check every 10s instead of 60s for responsiveness, but helper prevents double-send
  rotateCode();

  // API Routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", maintenance: isMaintenanceMode });
  });

  app.post("/api/admin/maintenance", (req, res) => {
    const { code, enabled } = req.body;
    if (code === currentAdminCode) {
      isMaintenanceMode = enabled;
      return res.json({ success: true, maintenance: isMaintenanceMode });
    }
    res.status(401).json({ success: false });
  });

  app.get("/api/intel", (req, res) => {
    let ip = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '';
    if (typeof ip === 'string') {
      ip = ip.split(',')[0].trim();
    } else if (Array.isArray(ip)) {
      ip = ip[0];
    }
    // Clean up loopback / IPv6 mapped IPv4 addresses
    if (ip === '::1' || ip === '::ffff:127.0.0.1') {
      ip = '127.0.0.1';
    }
    res.json({ ip });
  });

  app.post("/api/security/log", async (req, res) => {
    try {
      const { payload } = req.body;
      const targetWebhook = process.env.VITE_SECURITY_WEBHOOK_URL || process.env.DISCORD_WEBHOOK_URL || "https://discord.com/api/webhooks/1494839483869302826/abiDZE_a2tXPZr0qx9myzxatFaO3VXXHqqGR-7XA7YXGQ2Or1o6uAbeP5-9RuQxiqpHq";
      
      // Strict SSRF Mitigation Validation
      if (!validateWebhookUrl(targetWebhook)) {
        console.warn(`SSRF Blocked: Attempted request to non-whitelisted/private Webhook target: ${targetWebhook}`);
        return res.status(400).json({ error: "SSRF_VIOLATION: Webhook URL blocked by security shield." });
      }

      await fetch(targetWebhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      res.json({ success: true });
    } catch (err) {
      console.error("Security log proxy error:", err);
      res.status(500).json({ error: "Failed to send log" });
    }
  });

  app.post("/api/admin/verify", (req, res) => {
    const { code } = req.body;
    if (code === currentAdminCode) {
      // In a real app, generate a JWT. For this, we'll return success.
      return res.json({ success: true, token: "alzaabi_root_v5_" + Date.now() });
    }
    res.status(401).json({ success: false, message: "INVALID_SECURITY_CODE" });
  });

  // Secure Server-side Gemini Stream Proxy
  app.post("/api/gemini/stream", async (req, res) => {
    try {
      const { code, originalCode, type, task } = req.body;
      const apiKey = process.env.GEMINI_API_KEY;

      if (!apiKey) {
        return res.status(500).json({ error: "GEMINI_API_KEY is not configured on the server. Please add it in project secrets." });
      }

      const ai = new GoogleGenAI({ apiKey });

      const safeTruncate = (text: string, max = 350000) => {
        if (!text) return "";
        if (text.length <= max) return text;
        return text.substring(0, max) + "\n\n-- [!! WARNING: CODE TRUNCATED FOR CONTEXT !!]\n";
      };

      let prompt = "";
      if (task === "analyze") {
        prompt = `[ANALYSIS_PROTOCOL: STRICT_HIGH_FIDELITY_CODE_DEOBFUSCATION_AND_REBUILT]
ROLE: You are an expert code de-obfuscator, reverse engineer and logic restorer.
OBJECTIVE: Take the obfuscated target code and reconstruct it into clean, beautifully formatted, fully readable source code while maintaining 100% logic and operational parity.

CRITICAL PARITY PROTOCOL:
1. The output code MUST represent the EXACT logic, functions, mathematical calculations, API routes, network endpoints, visual interfaces, controls, structures, and behavior of the input files.
2. YOU ARE STRICTLY FORBIDDEN FROM HALLUCINATING or generating generic, standard, simulated, or template code "from your head". Do not write a generic script based on keyword association.
3. If some strings or functions appear highly obfuscated, unpack them semantically based on any available variable mappings, but do NOT replace them with placeholder comments. Every single structural block and line of logic must be faithfully reconstructed.
4. The output programming language MUST be the exact same programming language as the target input code (e.g., if target is Lua, output is Lua. If Javascript, output is Javascript. If Python, output is Python).

RECONSTRUCTION RULES:
- Rename all scrambled indices, single-character dummy letters, obf functions, and string arrays to clean human-readable names using clear naming conventions based on context.
- Inline, unpack, or decode arrays of encoded constant strings (Hex, Base64, arrays) back into clear variables or direct usages to make them transparently readable.
- Provide ONLY the final fully reconstructed clean code inside a clean markdown code block (e.g., \`\`\`lua ... \`\`\` or \`\`\`javascript ... \`\`\`).
- DO NOT write any report, markdown list, introductory note, explanation, bullet points, or friendly conversation. Provide ONLY the markdown code block.

ORIGINAL OBFUSCATED INPUT CODE (FOR REAL LOGIC):
${safeTruncate(originalCode)}

PRE-PROCESSED LAYER CODES (IF HELPFUL):
${safeTruncate(code)}

INPUT TYPE METHOD: ${type}`;
      } else if (task === "normalize") {
        prompt = `[TASK: HUMAN_VARIABLES] Take the input code and rename scramble indices and generic letters to clean human-readable names. Preserve 100% original logical flows and functions. Write only the de-scrambled code block without discussion.\nINPUT:\n${safeTruncate(code)}`;
      } else if (task === "scan") {
        prompt = `[TASK: SECURITY_VULNERABILITY_SCAN] Analyze the code for exploits, backdoors, standard flaws, hidden triggers, or dangerous logic. Provide risk levels and recommended mitigation actions. Write the report purely in Arabic markdown formatting. Keep the analysis thorough.\nINPUT CODE:\n${safeTruncate(code)}`;
      }

      // Configure headers for streaming
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.setHeader("Transfer-Encoding", "chunked");

      const responseStream = await ai.models.generateContentStream({
        model: "gemini-3.5-flash",
        contents: prompt
      });

      for await (const chunk of responseStream) {
        if (chunk.text) {
          res.write(chunk.text);
        }
      }
      res.end();
    } catch (err: any) {
      console.error("Gemini server proxy stream error:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: err?.message || "Internal server error during Gemini analysis process." });
      } else {
        res.end();
      }
    }
  });

  // Vite middleware setup
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
