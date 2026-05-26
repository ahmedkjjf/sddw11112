/**
 * Security Neural Firewall V5.0
 * Specialized protection against unauthorized access and debugging.
 */

import { collection, addDoc, serverTimestamp } from 'firebase/firestore';
import { db } from './firebase';

const lastSentMap = new Map<string, number>();
const COOLDOWN_MS = 60000; // 1 minute cooldown per event type

export async function logSecurityEvent(type: string, detail: string = 'No details', silent: boolean = false) {
  const now = Date.now();
  const lastSent = lastSentMap.get(type) || 0;

  if (now - lastSent < COOLDOWN_MS && !silent) {
    return; // Skip if in cooldown
  }

  if (!silent) lastSentMap.set(type, now);

  try {
    const visitorIntel = await getVisitorIntel();
    const ip = visitorIntel?.ip || 'Unknown';
    const location = visitorIntel?.location || 'Unknown';
    const networkInfo = `${visitorIntel?.network || 'Unknown'} (${visitorIntel?.asn || 'Unknown'})`;
    
    let mapUrl = '';
    if (visitorIntel?.coords?.lat) {
      mapUrl = `https://static-maps.yandex.ru/1.x/?ll=${visitorIntel.coords.lon},${visitorIntel.coords.lat}&size=450,450&z=13&l=sat&pt=${visitorIntel.coords.lon},${visitorIntel.coords.lat},pm2rdl`;
    }

    const clientInfo = {
      userAgent: navigator.userAgent,
      platform: navigator.platform,
      screen: `${window.screen.width}x${window.screen.height}`,
      cores: navigator.hardwareConcurrency || 'N/A',
      referrer: document.referrer || 'Direct'
    };

    // 1. Log to Cloud Database (Firestore) for Dashboard
    try {
      await addDoc(collection(db, 'security_logs'), {
        type,
        ip,
        location,
        details: detail,
        timestamp: serverTimestamp(),
        metadata: {
          ...clientInfo,
          network: networkInfo,
          battery: visitorIntel?.client?.battery || 'N/A',
          memory: visitorIntel?.client?.memory || 'N/A'
        }
      });
    } catch (e) {
      console.warn('Firestore logging failed', e);
    }

    // 2. Log to Discord Webhook
    if (!silent) {
      const payload: any = {
        embeds: [{
          title: `🚨 ${type.toUpperCase()}`,
          color: type.includes('LOCKOUT') || type.includes('BANNED') ? 0xff0000 : 0x00ff00,
          fields: [
            { name: 'IP_ADDRESS', value: `\`${ip}\``, inline: true },
            { name: 'TIMESTAMP', value: `\`${new Date().toISOString()}\``, inline: true },
            { name: 'LOCATION', value: `\`${location}\``, inline: false },
            { name: 'DETAIL', value: `\`\`\`${detail}\`\`\`` }
          ],
          footer: { text: 'Alzaabi Security Nexus' }
        }]
      };

      if (mapUrl) payload.embeds[0].image = { url: mapUrl };

      fetch('/api/security/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, payload })
      }).catch(() => {});
    }
  } catch (error) {
    console.warn('Security logging pipeline failed');
  }
}

export async function getVisitorIntel() {
  try {
    // 1. Try public IP resolver on client-side (most reliable for real visitor IPs in browser)
    let geoData: any = null;
    try {
      const geoResponse = await fetch('https://ipapi.co/json/');
      if (geoResponse.ok) {
        geoData = await geoResponse.json();
      }
    } catch (e) {
      console.warn('Direct client-side geo-IP resolution failed, trying proxy API fallback...');
    }

    // 2. Fallback 1: query server side endpoint, then query geo ip
    if (!geoData || !geoData.ip || geoData.ip === '127.0.0.1' || geoData.ip === 'Unknown') {
      let realIp = 'Unknown';
      try {
        const intelResp = await fetch('/api/intel');
        if (intelResp.ok) {
          const contentType = intelResp.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            const intelData = await intelResp.json();
            realIp = intelData.ip;
          }
        }
      } catch {}

      if (realIp && realIp !== 'Unknown' && realIp !== '127.0.0.1' && realIp !== '::1') {
        try {
          const geoResponse = await fetch(`https://ipapi.co/${realIp}/json/`);
          if (geoResponse.ok) {
            geoData = await geoResponse.json();
          }
        } catch {}
      }
    }

    // 3. Fallback 2: Use ipify, which is ultra run-time robust to grab the raw IP
    if (!geoData || !geoData.ip || geoData.ip === '127.0.0.1') {
      try {
        const ipifyResp = await fetch('https://api.ipify.org?format=json');
        if (ipifyResp.ok) {
          const ipifyData = await ipifyResp.json();
          if (ipifyData && ipifyData.ip) {
            try {
              const res2 = await fetch(`https://ipapi.co/${ipifyData.ip}/json/`);
              if (res2.ok) {
                geoData = await res2.json();
              } else {
                geoData = { ip: ipifyData.ip };
              }
            } catch {
              geoData = { ip: ipifyData.ip };
            }
          }
        }
      } catch {}
    }

    if (!geoData) {
      geoData = { ip: 'Unknown' };
    }
    
    // Attempt battery info
    let batteryInfo = 'N/A';
    try {
      const battery: any = await (navigator as any).getBattery?.();
      if (battery) {
        batteryInfo = `${Math.round(battery.level * 100)}% (${battery.charging ? 'Charging' : 'Discharging'})`;
      }
    } catch {}

    // Connection info
    const conn: any = (navigator as any).connection || (navigator as any).mozConnection || (navigator as any).webkitConnection;
    const connectionInfo = conn ? `${conn.effectiveType || 'Unknown'} (~${conn.downlink || '?'} Mbps)` : 'Unknown';

    let locationStr = 'Unknown';
    if (geoData.city || geoData.region || geoData.country_name) {
      const parts = [geoData.city, geoData.region, geoData.country_name].filter(p => p && p !== 'Unknown');
      locationStr = parts.length > 0 ? parts.join(', ') : 'Unknown';
    }

    return {
      ip: geoData.ip || 'Unknown',
      location: locationStr,
      coords: geoData.latitude ? { lat: geoData.latitude, lon: geoData.longitude } : undefined,
      network: geoData.org || 'Unknown',
      asn: geoData.asn || 'Unknown',
      timezone: geoData.timezone || 'Unknown',
      currency: geoData.currency || 'Unknown',
      postal: geoData.postal || 'Unknown',
      client: {
        ua: navigator.userAgent,
        platform: navigator.platform,
        screen: `${window.screen.width}x${window.screen.height}`,
        language: navigator.language,
        cores: navigator.hardwareConcurrency || 'N/A',
        memory: (navigator as any).deviceMemory ? `${(navigator as any).deviceMemory} GB` : 'N/A',
        battery: batteryInfo,
        connection: connectionInfo,
        cookies: navigator.cookieEnabled ? 'Enabled' : 'Disabled'
      }
    };
  } catch (e) {
    return null;
  }
}

// Anti-Debugger Loop
export function startAntiDebug() {
  const check = () => {
    (function () {
      return false;
    })
      ["constructor"]("debugger")
      ["call"]();
  };

  setInterval(() => {
    check();
  }, 5000);
}

// Detect if console is open via threshold
export function detectDevTools(onDetect: () => void) {
  const threshold = 300; // Increased threshold to avoid false positives with sidebars
  let devtoolsOpen = false;

  const check = () => {
    const widthDiff = Math.abs(window.outerWidth - window.innerWidth);
    const heightDiff = Math.abs(window.outerHeight - window.innerHeight);
    
    if ((widthDiff > threshold || heightDiff > threshold) && !devtoolsOpen) {
      devtoolsOpen = true;
      onDetect();
    } else if (widthDiff < threshold && heightDiff < threshold) {
      devtoolsOpen = false;
    }
  };

  window.addEventListener('resize', check);
  // Also try the console.log getter trick
  const devtools = {
    isOpen: false,
    orientation: undefined
  };
  const element = new Image();
  Object.defineProperty(element, 'id', {
    get: function () {
      if (!devtoolsOpen) {
        devtoolsOpen = true;
        onDetect();
      }
    }
  });
  console.log(element);
}

// Memory / Performance monitor to detect heavy probes
export function monitorPerformance(onAnomaly: () => void) {
  let lastTime = performance.now();
  
  setInterval(() => {
    const currentTime = performance.now();
    // Use a much higher threshold (3s) to avoid triggers on normal system lag or heavy AI streaming
    if (currentTime - lastTime > 3000) { 
      onAnomaly();
    }
    lastTime = currentTime;
  }, 1000); // Check every 1s
}

// Authorized Origin Validation
export function validateEnvironment(): boolean {
  const currentHost = window.location.hostname;
  
  // Allow localhost and local IP
  if (currentHost === 'localhost' || currentHost === '127.0.0.1' || !currentHost) return true;

  // Allow Netlify
  if (currentHost.includes('netlify.app')) return true;

  // Allow anything that contains the project identifier hash (6wp7ozzu7rxgl2k4y7cgsr)
  // This ensures legitimate AI Studio previews work without flickering
  if (currentHost.includes('6wp7ozzu7rxgl2k4y7cgsr')) return true;

  // Otherwise, block unauthorized clones
  console.error('CRITICAL: UNAUTHORIZED_DEPLOYMENT_DETECTED');
  logSecurityEvent('UNAUTHORIZED_DEPLOYMENT', `Host: ${currentHost}`);
  return false;
}
