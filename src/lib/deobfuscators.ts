import pako from 'pako';
import { ObfuscatorType, DeobfuscationResult } from '../types';

/**
 * Zlib Decompression
 */
function decompressZlib(input: string): string {
  try {
    // Try to convert string to Uint8Array. 
    // If it looks like hex, hex-decode first. 
    // If it's a binary string, convert carefully.
    let uint8: Uint8Array;
    
    if (/^[0-9a-fA-F]+$/.test(input.replace(/\s/g, ''))) {
      const hex = input.replace(/\s/g, '');
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
      uint8 = bytes;
    } else {
      const bytes = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) {
        bytes[i] = input.charCodeAt(i);
      }
      uint8 = bytes;
    }
    
    const decompressed = pako.inflate(uint8);
    return new TextDecoder().decode(decompressed);
  } catch (e) {
    throw new Error('فشل فك ضغط Zlib. تأكد من أن البيانات صحيحة.');
  }
}

/**
 * GSC Extraction (CoD Scripts)
 * Often contains a GSC header followed by Zlib data.
 */
function decompressGSC(input: string): string {
  try {
    // Look for Zlib header (0x78 0xDA or 0x78 0x9C or 0x78 0x01)
    // Sometimes it's raw binary, sometimes hex.
    let bytes: Uint8Array;
    
    if (/^[0-9a-fA-F\s]+$/.test(input.replace(/GSC[\s\S]*?\n/, ''))) {
      const hex = input.replace(/GSC[\s\S]*?\n/, '').replace(/\s/g, '');
      bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
      }
    } else {
      // Find start of Zlib block
      const zlibStart = input.indexOf('\x78\xDA');
      const start = zlibStart !== -1 ? zlibStart : input.indexOf('\x78\x9C');
      
      if (start === -1) {
        // Just try to inflate the whole thing if no header found
        const b = new Uint8Array(input.length);
        for (let i = 0; i < input.length; i++) b[i] = input.charCodeAt(i);
        bytes = b;
      } else {
        const sub = input.substring(start);
        bytes = new Uint8Array(sub.length);
        for (let i = 0; i < sub.length; i++) bytes[i] = sub.charCodeAt(i);
      }
    }

    const decompressed = pako.inflate(bytes);
    return new TextDecoder().decode(decompressed);
  } catch (e) {
    // If Zlib fails, it might be raw GSC. In that case, just return input or throw.
    return input; 
  }
}

/**
 * Base64 Decoding
 */
function decodeBase64(input: string): string {
  try {
    return atob(input.trim());
  } catch (e) {
    throw new Error('فشل فك تشفير Base64. تأكد من أن النص صحيح.');
  }
}

/**
 * Hex Decoding
 */
function decodeHex(input: string): string {
  try {
    const hex = input.replace(/\s/g, '').replace(/0x/g, '');
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  } catch (e) {
    throw new Error('فشل فك تشفير Hex. تأكد من أن القيمة المدخلة صحيحة.');
  }
}

/**
 * Simple Lua/JS Beautifier cleanup
 * Handles escaped chars like \61 or \x61
 */
function cleanupCode(input: string): string {
  // Convert \ decimal escapes like \65 -> 'A'
  let result = input.replace(/\\(\d{2,3})/g, (match, digit) => {
    const charCode = parseInt(digit, 10);
    return charCode < 256 ? String.fromCharCode(charCode) : match;
  });

  // Convert \x hex escapes like \x41 -> 'A'
  result = result.replace(/\\x([0-9A-Fa-f]{2})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  // Convert \u unicode escapes like \u0041 -> 'A'
  result = result.replace(/\\u([0-9A-Fa-f]{4})/g, (match, hex) => {
    return String.fromCharCode(parseInt(hex, 16));
  });

  return result;
}

export async function deobfuscate(type: ObfuscatorType, content: string): Promise<DeobfuscationResult> {
  const originalLength = content.length;
  
  try {
    let result = '';
    
    switch (type) {
      case 'Base64':
        result = decodeBase64(content);
        break;
      case 'Hex-Enc':
        result = decodeHex(content);
        break;
      case 'Zlib':
        result = decompressZlib(content);
        break;
      case 'GSC':
        result = decompressGSC(content);
        break;
      case 'Bytecode':
      case 'Asset':
        // For Bytecode and Asset, we pass the content directly to AI
        // as physical reconstruction requires the full context provided to Gemini.
        result = content;
        break;
      case 'Luraph':
      case 'MoonSec':
      case 'IronBrew':
      case 'Xenon':
      case 'PS-Obf':
      case 'Synapse':
      case 'Aclat':
      case 'Ganlv':
      case 'XOR':
        // For these, we apply general cleanup and beautification
        result = cleanupCode(content);
        break;
      default:
        result = content;
    }

    return {
      content: result,
      type,
      success: true,
      metadata: {
        type,
        originalLength,
        resultLength: result.length
      }
    };
  } catch (error: any) {
    return {
      content: '',
      type,
      success: false,
      message: error.message
    };
  }
}

export function detectObfuscator(content: string): ObfuscatorType | null {
  const low = content.toLowerCase();
  
  // Luraph Patterns
  if (low.includes('luraph') || low.includes('lph!') || content.includes('LPH_') || content.includes('Luraph_')) return 'Luraph';
  
  // MoonSec Patterns - often uses _MOONSEC_ or specific headers
  if (low.includes('moonsec') || low.includes('msec') || content.includes('_MOONSEC_')) return 'MoonSec';
  
  // IronBrew Patterns
  if (low.includes('ironbrew') || low.includes('brew') || content.includes('IB_')) return 'IronBrew';
  
  // Xenon Patterns
  if (low.includes('xenon') || content.includes('XENON_')) return 'Xenon';
  
  // PS-Obf Patterns
  if (low.includes('ps-obf') || content.includes('ps_obf')) return 'PS-Obf';
  
  // Synapse / Aclat Patterns
  if (low.includes('synapse') || content.includes('SYN_')) return 'Synapse';
  if (low.includes('aclat')) return 'Aclat';
  if (low.includes('ganlv') || low.includes('lua-simple-encrypt') || low.includes('bxor')) return 'Ganlv';
  if (low.includes('xor') || (low.includes('bit') && low.includes('bxor')) || (low.includes('string.byte') && low.includes('string.char') && low.includes('^'))) return 'XOR';

  // Check for common FiveM Lua obfuscation patterns (Large tables of numbers/strings)
  const luaTablePattern = /local\s+\w+\s*=\s*{\s*(\d+|0x[0-9a-fA-F]+)\s*(,\s*(\d+|0x[0-9a-fA-F]+))*\s*}/;
  if (luaTablePattern.test(content) && content.length > 500) {
    // If it's a huge table and doesn't match others, likely IronBrew or similar
    return 'IronBrew'; 
  }

  // Generic Lua VM patterns (often found in Luraph/MoonSec)
  if (content.includes('load(string.dump(function()')) return 'MoonSec';

  // Base64 check: must be long enough and match charset
  if (content.length > 20 && /^[A-Za-z0-9+/=]{20,}$/.test(content.trim().replace(/\s/g, ''))) {
    return 'Base64';
  }
  
  // Hex check
  const hexClean = content.replace(/0x/g, '').replace(/\s/g, '');
  if (hexClean.length > 20 && /^[0-9a-fA-F]{20,}$/.test(hexClean)) {
    return 'Hex-Enc';
  }

  return null;
}

export function extractTriggers(content: string): string[] {
  const triggers: Set<string> = new Set();
  
  if (!content) return [];

  // Helper to standardise trigger output
  const addTriggerVal = (type: string, name: string) => {
    const cleanName = name.replace(/['"\s]+/g, '').trim();
    if (cleanName && cleanName.length > 2 && cleanName.length < 120 && !cleanName.includes('\n')) {
      // Avoid raw code leftovers
      if (!/^[=()[\]{}]+$/.test(cleanName)) {
        triggers.add(`${type}: ${cleanName}`);
      }
    }
  };

  // 1. Core Native Extraction Regexes
  // TriggerEvents: TriggerServerEvent, TriggerClientEvent, TriggerEvent, TriggerLatentServerEvent, TriggerLatentClientEvent etc.
  const triggerRegex = /(?:TriggerServerEvent|TriggerClientEvent|TriggerEvent|TriggerLatentServerEvent|TriggerLatentClientEvent|SendNUIMessage)\s*\(\s*['"]([^'"]+)['"]/gi;
  let match;
  while ((match = triggerRegex.exec(content)) !== null) {
    if (match[1]) {
      addTriggerVal('TriggerEvent', match[1]);
    }
  }

  // RegisterNetEvents & AddEventHandlers
  const eventHookRegex = /(?:RegisterNetEvent|RegisterServerEvent|RegisterClientEvent|AddEventHandler)\s*\(\s*['"]([^'"]+)['"]/gi;
  while ((match = eventHookRegex.exec(content)) !== null) {
    if (match[1]) {
      addTriggerVal('RegisterEvent', match[1]);
    }
  }

  // Generic Function Triggering (e.g. triggerEvent('someEvent', ...))
  const genericTriggerRegex = /(?:triggerEvent|RegisterEvent|registerNetEvent|addEventHandler|TriggerServer|TriggerClient)\s*\(\s*['"]([^'"]+)['"]/gi;
  while ((match = genericTriggerRegex.exec(content)) !== null) {
    if (match[1]) {
      addTriggerVal('TriggerEvent', match[1]);
    }
  }

  // Also extract string parameters of custom TriggerEvent calls that might use dynamic variables
  // e.g. TriggerServerEvent(variable) -> we want to pull strings that look like FiveM event names (e.g., contains : or -)

  // 2. Scan and extract all string literals in the file to inspect if they represent hidden Event Names/Triggers!
  // This is highly effective if the file is obfuscated, as all events are stored in a string dict.
  // Match single/double quoted strings, as well as Lua [===[long strings]===]
  const stringLiteralsRegex = /(?:['"])([^'"\\\r\n]+)(?:['"])|(?:\[=*\[)([\s\S]*?)(?:\]=*\])/g;
  const potentialStrings: string[] = [];
  while ((match = stringLiteralsRegex.exec(content)) !== null) {
    const str = match[1] || match[2];
    if (str) potentialStrings.push(str);
  }

  // 3. Scan for Hex & Dec byte array blocks that might represent strings
  // Lua decimal arrays: {101, 115, 120, 58, ...}
  const decArrayRegex = /\{\s*(\d+)(?:\s*,\s*(\d+)){3,}\s*\}/g;
  while ((match = decArrayRegex.exec(content)) !== null) {
    try {
      const fullMatch = match[0];
      const decimals = fullMatch.match(/\d+/g);
      if (decimals) {
        let decoded = '';
        for (const dec of decimals) {
          const charCode = parseInt(dec, 10);
          if (charCode >= 32 && charCode <= 126) {
            decoded += String.fromCharCode(charCode);
          }
        }
        if (decoded.length >= 4) {
          potentialStrings.push(decoded);
        }
      }
    } catch (e) { /* ignore */ }
  }

  // Hex sequences in string arrays or code (e.g. \x65\x73\x78\x3a)
  const hexSequenceRegex = /(?:\\x[0-9a-fA-F]{2})+/g;
  while ((match = hexSequenceRegex.exec(content)) !== null) {
    try {
      const hexStr = match[0];
      const bytes = hexStr.match(/[0-9a-fA-F]{2}/g);
      if (bytes) {
        let decoded = '';
        for (const byte of bytes) {
          decoded += String.fromCharCode(parseInt(byte, 16));
        }
        if (decoded.length >= 4) {
          potentialStrings.push(decoded);
        }
      }
    } catch (e) { /* ignore */ }
  }

  // 4. Try to parse potential strings for patterns suggesting they are events/triggers
  const commonFrameWorks = /^(esx:|qb-|vrp:|lscustom|phone:|bank:|police:|gang:|job:|admin:|utility:|discord:|core:|hud:|chat:|weapon:|vehicle:|inventory:)/i;
  const eventIndicators = /(_event|event_|trigger|net_event|handler|payload|server:|client:|sync:|callback:|check:|verify:|hook:)/i;

  for (const rawStr of potentialStrings) {
    const cleanStr = rawStr.trim();
    if (cleanStr.length < 3 || cleanStr.length > 80) continue;

    // Direct check: Does it look like an Event name?
    // Trigger names often have colons (esx:getPlayer) or dashes (qb-weapons:equip) or dots or underscores
    const hasColon = cleanStr.includes(':');
    const hasDash = cleanStr.includes('-');
    const isFiveMPattern = commonFrameWorks.test(cleanStr) || eventIndicators.test(cleanStr);
    
    if (isFiveMPattern) {
      if (cleanStr.toLowerCase().includes('trigger')) {
        addTriggerVal('TriggerEvent', cleanStr);
      } else {
        addTriggerVal('ObfuscatedEvent', cleanStr);
      }
    } else if (hasColon && /^[a-zA-Z0-9_\-:]+$/.test(cleanStr)) {
      addTriggerVal('ObfuscatedEvent', cleanStr);
    } else if (hasDash && cleanStr.length > 8 && /^[a-zA-Z0-9_\-]+$/.test(cleanStr) && (cleanStr.includes('server') || cleanStr.includes('client') || cleanStr.includes('event') || cleanStr.includes('trigger') || cleanStr.includes('hook') || cleanStr.includes('hud') || cleanStr.includes('menu'))) {
      addTriggerVal('ObfuscatedEvent', cleanStr);
    } else if (/^[A-Za-z0-9+/=]{16,}$/.test(cleanStr)) {
      // Try Base64 decoding inside the string list
      try {
        const decoded = atob(cleanStr);
        if (/^[a-zA-Z0-9_\-:]{4,80}$/.test(decoded)) {
          addTriggerVal('Base64DecodedEvent', decoded);
        }
      } catch (e) { /* ignore */ }
    }
  }

  // Keep a direct regex to extract any general string containing typical trigger format
  // to ensure nothing gets missed
  const fallbackRegex = /['"]([a-zA-Z0-9_\-:]+:[a-zA-Z0-9_\-:]+)['"]/gi;
  while ((match = fallbackRegex.exec(content)) !== null) {
    if (match[1]) {
      addTriggerVal('ObfuscatedEvent', match[1]);
    }
  }

  // And specifically make sure if "TriggerEvent" or "TriggerServerEvent" is inside a Lua table array
  // we extract all strings from nearby items. If they include words like "TriggerEvent", we flag everything.

  return Array.from(triggers);
}
