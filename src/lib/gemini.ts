/**
 * Truncates code text to protect the model from context overflow (1,048,576 tokens limit)
 * Max 400,000 characters is approximately 100k - 130k tokens, which is extremely safe and generous.
 */
function truncateCode(text: string, maxCharacters = 400000): string {
  if (!text) return "";
  if (text.length <= maxCharacters) return text;
  return text.substring(0, maxCharacters) + "\n\n-- [!! WARNING: CODE TRUNCATED TO FIT CONTEXT CONSTRAINTS !!]\n-- [!! تم اقتطاع جزء من الكود لملاءمة حجم الذاكرة بالذكاء الاصطناعي !!]\n";
}

/**
 * Streams chunky data from server-side proxy
 */
async function runStreamingProxyFetch(task: string, payload: any, onChunk: (text: string) => void): Promise<string> {
  const response = await fetch("/api/gemini/stream", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...payload, task })
  });

  if (!response.ok) {
    // If the endpoint returned 444, 404, or is on static Netlify host, explain gracefully.
    const isNetlify = window.location.hostname.includes("netlify.app");
    if (response.status === 404 || isNetlify) {
      throw new Error("سيرفر الذكاء الاصطناعي غير نشط على استضافة سكونية (Netlify). يرجى تشغيل الموقع محلياً أو استضافته على خادم يدعم سيرفر كامل (مثل Cloud Run).");
    }
    const errText = await response.text();
    let errJson;
    try { errJson = JSON.parse(errText); } catch { /* ignore */ }
    throw new Error(errJson?.error || errText || "فشل الاتصال بسيرفر الذكاء الاصطناعي.");
  }

  const reader = response.body?.getReader();
  if (!reader) {
    throw new Error("سيرفر الذكاء الاصطناعي لم يستجب بهيئة بث (ReadableStream).");
  }

  const decoder = new TextDecoder("utf-8");
  let fullText = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunkText = decoder.decode(value, { stream: true });
    fullText += chunkText;
    onChunk(fullText);
  }

  return fullText;
}

export async function analyzeCodeStream(code: string, originalCode: string, type: string, onChunk: (text: string) => void) {
  try {
    const safeOriginal = truncateCode(originalCode, 400000);
    const safeOutput = truncateCode(code, 400000);

    return await runStreamingProxyFetch("analyze", {
      code: safeOutput,
      originalCode: safeOriginal,
      type
    }, onChunk);
  } catch (error: any) {
    console.error("AI Analysis Error:", error);
    throw error;
  }
}

export async function normalizeVariablesStream(code: string, onChunk: (text: string) => void) {
  try {
    const safeOutput = truncateCode(code, 400000);
    return await runStreamingProxyFetch("normalize", { code: safeOutput }, onChunk);
  } catch (error: any) {
    console.error("Variable Normalization Error:", error);
    throw error;
  }
}

export async function scanVulnerabilitiesStream(code: string, onChunk: (text: string) => void) {
  try {
    const safeOutput = truncateCode(code, 400000);
    return await runStreamingProxyFetch("scan", { code: safeOutput }, onChunk);
  } catch (error: any) {
    console.error("Vulnerability Scan Error:", error);
    throw error;
  }
}
