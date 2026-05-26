import { GoogleGenAI } from "@google/genai";

let aiInstance: GoogleGenAI | null = null;

function getAi() {
  if (!aiInstance) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is missing. Please check Settings > Secrets.');
    }
    aiInstance = new GoogleGenAI({ apiKey: apiKey });
  }
  return aiInstance;
}

/**
 * Truncates code text to protect the model from context overflow (1,048,576 tokens limit)
 * Max 400,000 characters is approximately 100k - 130k tokens, which is extremely safe and generous.
 */
function truncateCode(text: string, maxCharacters = 400000): string {
  if (!text) return "";
  if (text.length <= maxCharacters) return text;
  return text.substring(0, maxCharacters) + "\n\n-- [!! WARNING: CODE TRUNCATED TO FIT CONTEXT CONSTRAINTS !!]\n-- [!! تم اقتطاع جزء من الكود لملاءمة حجم الذاكرة بالذكاء الاصطناعي !!]\n";
}

export async function analyzeCodeStream(code: string, originalCode: string, type: string, onChunk: (text: string) => void) {
  try {
    const ai = getAi();
    
    // Safely truncate inputs to protect context limit from oversized files
    const safeOriginal = truncateCode(originalCode, 400000);
    const safeOutput = truncateCode(code, 400000);

    const prompt = `[ANALYSIS_PROTOCOL: STRICT_HIGH_FIDELITY_CODE_DEOBFUSCATION_AND_REBUILT]
ROLE: You are an expert code de-obfuscator, reverse engineer and logic restorer.
OBJECTIVE: Take the obfuscated target code and reconstruct it into clean, beautifully formatted, fully readable source code while maintaining 100% logic and operational parity.

CRITICAL PARITY PROTOCOL:
1. The output code MUST represent the EXACT logic, functions, mathematical calculations, API routes, network endpoints, visual interfaces, controls, structures, and behavior of the input files.
2. YOU ARE STRICTLY FORBIDDEN FROM HALLUCINATING or generating generic, standard, simulated, or template code "from your head". Do not write a generic script based on keyword association (for example, if the script is for a specific game hook, do NOT write a standard admin script template unless those precise features exist in the target code).
3. If some strings or functions appear highly obfuscated, unpack them semantically based on any available variable mappings, but do NOT replace them with placeholder comments like "// ... rest of the code". Every single structural block and line of logic must be faithfully reconstructed.
4. The output programming language MUST be the exact same programming language as the target input code (e.g., if target is Lua, output is Lua. If Javascript, output is Javascript. If Python, output is Python).

RECONSTRUCTION RULES:
- Rename all scrambled indices, single-character dummy letters, obf functions, and string arrays to clean human-readable names using clear naming conventions based on context.
- Inline, unpack, or decode arrays of encoded constant strings (Hex, Base64, arrays) back into clear variables or direct usages to make them transparently readable.
- Provide ONLY the final fully reconstructed clean code inside a clean markdown code block (e.g., \`\`\`lua ... \`\`\` or \`\`\`javascript ... \`\`\`).
- DO NOT write any report, markdown list, introductory note, explanation, bullet points, or friendly conversation. Provide ONLY the markdown code block.

ORIGINAL OBFUSCATED INPUT CODE (FOR REAL LOGIC):
${safeOriginal}

PRE-PROCESSED LAYER CODES (IF HELPFUL):
${safeOutput}

INPUT TYPE METHOD: ${type}`;
    
    const response = await ai.models.generateContentStream({
      model: "gemini-3.5-flash",
      contents: prompt
    });

    let fullText = "";
    for await (const chunk of response) {
      const text = chunk.text;
      fullText += text;
      onChunk(fullText);
    }
    return fullText;
  } catch (error: any) {
    console.error("AI Analysis Error:", error);
    throw error;
  }
}

export async function normalizeVariablesStream(code: string, onChunk: (text: string) => void) {
  try {
    const ai = getAi();
    const truncated = truncateCode(code, 400000);
    const prompt = `[TASK: HUMAN_VARIABLES] 1. RENAME GENERIC VARS. 2. DO NOT CHANGE LOGIC. 3. OUTPUT ONLY CODE BLOCK.\nINPUT:\n${truncated}`;
    
    const response = await ai.models.generateContentStream({
      model: "gemini-3.5-flash",
      contents: prompt
    });

    let fullText = "";
    for await (const chunk of response) {
      const text = chunk.text;
      fullText += text;
      onChunk(fullText);
    }
    return fullText;
  } catch (error: any) {
    console.error("Variable Normalization Error:", error);
    throw error;
  }
}

export async function scanVulnerabilitiesStream(code: string, onChunk: (text: string) => void) {
  try {
    const ai = getAi();
    const truncated = truncateCode(code, 400000);
    const prompt = `[TASK: SECURITY_VULNERABILITY_SCAN] ANALYZE FOR FLAWS, BACKDOORS. PROVIDE RISK LEVELS. OUTPUT IN ARABIC MARKDOWN.\nINPUT CODE:\n${truncated}`;
    
    const response = await ai.models.generateContentStream({
      model: "gemini-3.5-flash",
      contents: prompt
    });

    let fullText = "";
    for await (const chunk of response) {
      const text = chunk.text;
      fullText += text;
      onChunk(fullText);
    }
    return fullText;
  } catch (error: any) {
    console.error("Vulnerability Scan Error:", error);
    throw error;
  }
}
