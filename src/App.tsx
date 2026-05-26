/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef, useMemo } from 'react';
import Markdown from 'react-markdown';
import { 
  FileCode2, 
  Terminal, 
  ShieldAlert, 
  Copy, 
  Trash2, 
  Zap, 
  BrainCircuit, 
  Info,
  ChevronRight,
  ChevronLeft,
  ArrowUp,
  ArrowDown,
  Database,
  Lock,
  Binary,
  Download,
  Search,
  Activity,
  Cpu,
  Radio,
  Radar,
  Upload,
  Layers,
  ShieldCheck,
  ZapOff,
  Wand2,
  ListRestart,
  X,
  MapPin,
  Globe,
  Wifi,
  Battery,
  User,
  Monitor,
  MessageSquare
} from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { atomDark } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { motion, AnimatePresence } from 'motion/react';
import { ObfuscatorType, DeobfuscationResult } from './types';
import { deobfuscate, detectObfuscator, extractTriggers } from './lib/deobfuscators';
import { analyzeCodeStream, normalizeVariablesStream, scanVulnerabilitiesStream } from './lib/gemini';
import { CustomCursor } from './components/CustomCursor';
import { BackgroundMusic } from './components/BackgroundMusic';

import { logSecurityEvent, detectDevTools, monitorPerformance, getVisitorIntel, validateEnvironment } from './lib/security';
import { doc, getDoc, setDoc, updateDoc, onSnapshot, serverTimestamp, increment, collection, addDoc, query, where, orderBy, limit, deleteDoc, getDocs } from 'firebase/firestore';
import { db } from './lib/firebase';

const OBFS: ObfuscatorType[] = [
  'Luraph', 'MoonSec', 'Xenon', 'IronBrew', 'PS-Obf', 'Synapse', 'Aclat', 'Ganlv', 'XOR', 'Base64', 'Hex-Enc', 'Zlib', 'GSC', 'Bytecode', 'Asset', 'Protector', 'VM-Obf', 'K-Deobf', 'Minified'
];

export default function App() {
  const [selectedObfs, setSelectedObfs] = useState<ObfuscatorType[]>(['Luraph']);
  const textRef = useRef<HTMLTextAreaElement>(null);
  const [input, setInput] = useState('');
  const [output, setOutput] = useState<DeobfuscationResult | null>(null);
  const [displayedContent, setDisplayedContent] = useState('');
  const [isScrambling, setIsScrambling] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);
  const [status, setStatus] = useState<string>('SYSTEM_READY');
  const [isAutoDetected, setIsAutoDetected] = useState(false);
  const [triggers, setTriggers] = useState<string[]>([]);
  const [uid, setUid] = useState('285637FB');
  const [systemLogs, setSystemLogs] = useState<{msg: string, type: 'info' | 'warn' | 'success'}[]>([]);
  const [securityScore, setSecurityScore] = useState(0);
  const [isNormalizing, setIsNormalizing] = useState(false);
  const [isScanningVulnerabilities, setIsScanningVulnerabilities] = useState(false);
  // Removed login states
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [historyLogs, setHistoryLogs] = useState<any[]>([]);
  const [visitorIntel, setVisitorIntel] = useState<any>(null);
  const [isIntelOpen, setIsIntelOpen] = useState(false);
  const [isAuthorized, setIsAuthorized] = useState(() => validateEnvironment());
  const [activeTab, setActiveTab] = useState<'SOURCE' | 'ANALYSIS' | 'LOGS' | 'SECURITY'>('SOURCE');
  const [isV2Ready, setIsV2Ready] = useState(false);
  const [stats, setStats] = useState({ complexity: 0, density: 0, entropy: 0 });
  const [globalBans, setGlobalBans] = useState<any[]>([]);
  const [banType, setBanType] = useState<'IP' | 'DEVICE' | 'UNBAN'>('IP');
  const [adminAlertMessage, setAdminAlertMessage] = useState('');
  const [adminAlertEnabled, setAdminAlertEnabled] = useState(false);
  const [adminAlertType, setAdminAlertType] = useState<'RED' | 'GREEN' | 'YELLOW'>('RED');
  const [deviceFingerprint, setDeviceFingerprint] = useState('');
  const [manualIp, setManualIp] = useState('');
  const [manualReason, setManualReason] = useState('');
  const [manualDuration, setManualDuration] = useState('3600000'); // Default 1 hour
  const [autoBanEnabled, setAutoBanEnabled] = useState(false);
  const [lockoutUntil, setLockoutUntil] = useState<number | null>(null); // Emergency clear
  const [lockoutReason, setLockoutReason] = useState<string>('REASON_UNSPECIFIED');
  const [isAdminAuthenticated, setIsAdminAuthenticated] = useState(() => sessionStorage.getItem('alzaabi_admin_auth') === 'true');
  const [adminCodeInput, setAdminCodeInput] = useState('');
  const [loginError, setLoginError] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isMaintenance, setIsMaintenance] = useState(false);
  const [copiedText, setCopiedText] = useState<{ [key: string]: boolean }>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [currentMatchIndex, setCurrentMatchIndex] = useState(0);

  const matchingLineNumbers = useMemo(() => {
    if (!searchQuery || !displayedContent) return [];
    const lines = displayedContent.split('\n');
    const indexes: number[] = [];
    const lowerQuery = searchQuery.toLowerCase();
    lines.forEach((line, index) => {
      if (line.toLowerCase().includes(lowerQuery)) {
        indexes.push(index + 1);
      }
    });
    return indexes;
  }, [searchQuery, displayedContent]);

  useEffect(() => {
    setCurrentMatchIndex(0);
  }, [searchQuery]);

  useEffect(() => {
    if (!isAuthorized) {
      // Complete self-destruct inside unauthorized clone environments
      try {
        document.title = '404 Not Found';
        if (document.body) {
          document.body.innerHTML = '';
          document.body.style.backgroundColor = '#ffffff';
          document.body.style.color = '#ffffff';
        }
        const rootDiv = document.getElementById('root');
        if (rootDiv) {
          rootDiv.innerHTML = '';
          rootDiv.style.display = 'none';
        }
      } catch (e) { /* ignore safe-checks */ }
      
      const style = document.createElement('style');
      style.innerHTML = `
        html, body, #root, * {
          background-color: #ffffff !important;
          color: #ffffff !important;
          background: #ffffff !important;
          display: none !important;
          opacity: 0 !important;
          visibility: hidden !important;
          pointer-events: none !important;
        }
      `;
      document.head.appendChild(style);
    }
  }, [isAuthorized]);

  const handleNextMatch = () => {
    if (matchingLineNumbers.length === 0) return;
    const nextIndex = (currentMatchIndex + 1) % matchingLineNumbers.length;
    setCurrentMatchIndex(nextIndex);
    scrollToLine(matchingLineNumbers[nextIndex]);
  };

  const handlePrevMatch = () => {
    if (matchingLineNumbers.length === 0) return;
    const prevIndex = (currentMatchIndex - 1 + matchingLineNumbers.length) % matchingLineNumbers.length;
    setCurrentMatchIndex(prevIndex);
    scrollToLine(matchingLineNumbers[prevIndex]);
  };

  const scrollToLine = (lineNumber: number) => {
    setTimeout(() => {
      const element = document.getElementById(`code-line-${lineNumber}`);
      if (element) {
        element.scrollIntoView({
          behavior: 'smooth',
          block: 'center',
          inline: 'nearest'
        });
      }
    }, 50);
  };

  useEffect(() => {
    const generateFingerprintLocal = () => {
      const components = [
        navigator.userAgent,
        navigator.language,
        window.screen.width,
        window.screen.height,
        navigator.hardwareConcurrency || 'N/A',
        (navigator as any).deviceMemory || 'N/A'
      ];
      const str = components.join('|');
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
      }
      return 'FPR-' + Math.abs(hash).toString(16).toUpperCase();
    };

    let fp = localStorage.getItem('alzaabi_device_fingerprint');
    if (!fp) {
      fp = generateFingerprintLocal();
      localStorage.setItem('alzaabi_device_fingerprint', fp);
    }
    setDeviceFingerprint(fp);
  }, []);

  useEffect(() => {
    if (!isAdminAuthenticated) return;
    
    // Fetch Live Security Logs for the Admin Feed
    const q = query(collection(db, 'security_logs'), orderBy('timestamp', 'desc'), limit(100));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const logs = snapshot.docs.map(d => ({ id: d.id, ...d.data() }));
      setHistoryLogs(logs);
      addLog(`ADMIN_SYNC: ${logs.length} SECURITY_LOGS_LOADED`, 'success');
    }, (error) => {
      console.error("Firestore Error [security_logs]:", error.message);
      addLog('ADMIN_SYNC_ERROR: SECURITY_LOGS_FAIL', 'warn');
    });
    
    return () => unsubscribe();
  }, [isAdminAuthenticated]);

  useEffect(() => {
    const checkMaintenance = async () => {
      try {
        const resp = await fetch('/api/health');
        if (!resp.ok) return;
        const contentType = resp.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          const data = await resp.json();
          setIsMaintenance(!!data.maintenance);
        }
      } catch (e) {
        // Silent fail or minimal log
        console.warn("Maintenance check background sync failed");
      }
    };
    
    checkMaintenance();
    const interval = setInterval(checkMaintenance, 30000); // Check every 30s
    return () => clearInterval(interval);
  }, []);

  const handleAdminLogin = async () => {
    setIsLoggingIn(true);
    setLoginError('');
    try {
      const resp = await fetch('/api/admin/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: adminCodeInput })
      });
      const data = await resp.json();
      if (data.success) {
        setIsAdminAuthenticated(true);
        sessionStorage.setItem('alzaabi_admin_auth', 'true');
        sessionStorage.setItem('alzaabi_admin_auth_code', adminCodeInput);
        addLog('KEY_AUTH_SUCCESS: ACCESS_GRANTED', 'success');
      } else {
        setLoginError('INVALID_SECURITY_CODE');
        addLog('KEY_AUTH_FAILURE: INVALID_CODE_ATTEMPT', 'warn');
      }
    } catch (e) {
      setLoginError('AUTH_SERVER_ERROR');
    } finally {
      setIsLoggingIn(false);
    }
  };

  useEffect(() => {
    // Sync System Config
    const unsub = onSnapshot(doc(db, 'system_config', 'security'), (snapshot) => {
      if (snapshot.exists()) {
        const data = snapshot.data() as any;
        setAutoBanEnabled(!!data.autoBanEnabled);
        setAdminAlertMessage(data.adminAlertMessage || '');
        setAdminAlertEnabled(!!data.adminAlertEnabled);
        setAdminAlertType(data.adminAlertType || 'RED');
      } else {
        // Init default if not exists
        setDoc(doc(db, 'system_config', 'security'), { 
          autoBanEnabled: false, 
          adminAlertMessage: '',
          adminAlertEnabled: false,
          adminAlertType: 'RED',
          updatedAt: serverTimestamp() 
        });
      }
    }, (error) => {
      console.error('Firestore Error [system_config]: ', error.message);
    });
    return () => unsub();
  }, []);

  const handleUpdateAnnouncement = async (msg: string, enabled: boolean, type: 'RED' | 'GREEN' | 'YELLOW') => {
    try {
      await setDoc(doc(db, 'system_config', 'security'), {
        autoBanEnabled: autoBanEnabled,
        adminAlertMessage: msg,
        adminAlertEnabled: enabled,
        adminAlertType: type,
        updatedAt: serverTimestamp()
      }, { merge: true });
      addLog(`ANNOUNCEMENT_UPDATED: MESSAGE_${enabled ? 'PUBLISHED' : 'DEACTIVATED'}`, 'success');
    } catch (e) {
      addLog('FAILED_TO_UPDATE_ANNOUNCEMENT', 'warn');
    }
  };

  const toggleAutoBan = async () => {
    try {
      await setDoc(doc(db, 'system_config', 'security'), {
        autoBanEnabled: !autoBanEnabled,
        updatedAt: serverTimestamp()
      }, { merge: true });
      addLog(`SYSTEM_CONFIG: AUTO_BAN_${!autoBanEnabled ? 'ENABLED' : 'DISABLED'}`, 'success');
    } catch (e) {
      addLog('FAILED_TO_UPDATE_CONFIG', 'warn');
    }
  };

  useEffect(() => {
    // Emergency Unban for the current developer/user session
    const performEmergencyUnban = async () => {
      localStorage.removeItem('alzaabi_lockout');
      localStorage.removeItem('alzaabi_lockout_reason');
      setLockoutUntil(null);
      setIsAuthorized(true);
      setStatus('SYSTEM_READY');

      if (visitorIntel?.ip) {
        try {
          const q = query(collection(db, 'banned_ips'), where('ip', '==', visitorIntel.ip));
          const snapshots = await getDocs(q);
          for (const d of snapshots.docs) {
            await deleteDoc(d.ref);
          }
          addLog('DEV_BYPASS: BANS_CLEARED_FOR_CURRENT_IP', 'success');
        } catch (e) {
          console.error("Cleanup error:", e);
        }
      }
    };
    performEmergencyUnban();
  }, [visitorIntel?.ip]);

  useEffect(() => {
    // Global filter for benign media/network abort errors
    const handleGlobalError = (event: ErrorEvent | PromiseRejectionEvent) => {
      let message = '';
      let name = '';
      let code = 0;

      if ('reason' in event) {
        message = event.reason?.message || '';
        name = event.reason?.name || '';
        code = event.reason?.code || 0;
      } else {
        message = event.message || '';
        if (event.error) {
          name = event.error.name || '';
          code = event.error.code || 0;
          if (!message && event.error.message) message = event.error.message;
        }
      }
      
      const isBenignMediaError = 
        message.toLowerCase().includes('abort') || 
        message.toLowerCase().includes('user\'s request') ||
        message.toLowerCase().includes('user agent') ||
        message.toLowerCase().includes('interrupted') ||
        name === 'AbortError' ||
        code === 20;

      if (isBenignMediaError) {
        if (event instanceof ErrorEvent) {
          event.preventDefault();
          event.stopImmediatePropagation();
        }
        return;
      }
    };

    window.addEventListener('error', handleGlobalError);
    window.addEventListener('unhandledrejection', handleGlobalError);

    return () => {
      window.removeEventListener('error', handleGlobalError);
      window.removeEventListener('unhandledrejection', handleGlobalError);
    };
  }, []);

  const [timeLeft, setTimeLeft] = useState<string>('');

  useEffect(() => {
    if (!lockoutUntil) return;

    const interval = setInterval(() => {
      const remaining = lockoutUntil - Date.now();
      if (remaining <= 0) {
        setLockoutUntil(null);
        localStorage.removeItem('alzaabi_lockout');
        setTimeLeft('');
        clearInterval(interval);
      } else {
        const h = Math.floor(remaining / 3600000);
        const m = Math.floor((remaining % 3600000) / 60000);
        const s = Math.floor((remaining % 60000) / 1000);
        setTimeLeft(`${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [lockoutUntil]);

  useEffect(() => {
    const q = query(collection(db, 'banned_ips'), orderBy('timestamp', 'desc'));
    const unsubscribe = onSnapshot(q, (snapshot) => {
      const bans = snapshot.docs.map(d => ({ id: d.id, ...d.data() })) as any[];
      setGlobalBans(bans);
      
      // Check if current user is globally banned (IP or Device Fingerprint)
      const currentIp = visitorIntel?.ip;
      const currentFP = deviceFingerprint || localStorage.getItem('alzaabi_device_fingerprint');
      
      if (currentIp || currentFP) {
        const ban = bans.find((b: any) => 
          (b.type === 'DEVICE' && b.ip === currentFP) ||
          (b.type === 'IP' && b.ip === currentIp) ||
          (!b.type && b.ip === currentIp) // support legacy bans
        );
        if (ban && (ban as any).expiresAt > Date.now()) {
          setLockoutUntil((ban as any).expiresAt);
          setLockoutReason((ban as any).reason);
          setIsAuthorized(false);
          setStatus('IP_BANNED');
        }
      }
    }, (error) => {
      console.error("Firestore Error [banned_ips]:", error.message);
    });
    return () => unsubscribe();
  }, [visitorIntel?.ip, deviceFingerprint]);

  const triggerLockout = async (reason: string) => {
    if (!autoBanEnabled) {
      addLog(`SECURITY_ALERT: ${reason} (BAN_DISABLED_BY_KEY)`, 'warn');
      logSecurityEvent('SECURITY_BYPASS_MODE', `Violation detected but auto-ban is disabled: ${reason}`);
      setStatus('ACCESS_LOCKED');
      setIsAuthorized(false);
      return;
    }

    const duration = 3600000; // 1 hour
    const newLockout = Date.now() + duration;
    setLockoutUntil(newLockout);
    setLockoutReason(reason);
    localStorage.setItem('alzaabi_lockout', newLockout.toString());
    localStorage.setItem('alzaabi_lockout_reason', reason);
    
    // Add to Firebase for global tracking
    try {
      await addDoc(collection(db, 'banned_ips'), {
        ip: visitorIntel?.ip || 'UNKNOWN',
        reason: reason,
        timestamp: serverTimestamp(),
        expiresAt: newLockout,
        visitorData: visitorIntel || {}
      });
    } catch (e) {
      console.error("Cloud ban sync error:", e);
    }

    addLog(`CRITICAL: IP_BANNED [1_HOUR] // REASON: ${reason}`, 'warn');
    logSecurityEvent('SECURITY_LOCKOUT', `Violation: ${reason}`);
    setStatus('IP_BANNED');
    setIsAuthorized(false);
  };

  const handleUnban = async (banId: string) => {
    try {
      await deleteDoc(doc(db, 'banned_ips', banId));
      addLog('IP_UNBANNED_SUCCESS', 'success');
    } catch (e) {
      addLog('FAILED_TO_UNBAN', 'warn');
    }
  };

  const handleManualBan = async () => {
    if (banType === 'UNBAN') {
      if (!manualIp) {
        addLog('WARN: MISSING_IP_OR_FINGERPRINT_FOR_UNBAN', 'warn');
        return;
      }
      try {
        const q0 = query(collection(db, 'banned_ips'), where('ip', '==', manualIp));
        const snapshots = await getDocs(q0);
        if (snapshots.empty) {
          addLog(`WARN: NO_ACTIVE_BAN_FOUND_FOR // ${manualIp}`, 'warn');
          return;
        }
        for (const d of snapshots.docs) {
          await deleteDoc(d.ref);
        }
        setManualIp('');
        addLog(`MANUAL_UNBAN_SUCCESS // ${manualIp}`, 'success');
      } catch (e) {
        addLog('FAILED_TO_EXECUTE_UNBAN', 'warn');
      }
      return;
    }

    if (!manualIp || !manualReason) {
      addLog('WARN: MISSING_BAN_DATA', 'warn');
      return;
    }
    try {
      const duration = parseInt(manualDuration);
      await addDoc(collection(db, 'banned_ips'), {
        ip: manualIp,
        reason: manualReason,
        timestamp: serverTimestamp(),
        expiresAt: Date.now() + duration,
        type: banType // 'IP' or 'DEVICE'
      });
      setManualIp('');
      setManualReason('');
      addLog(`MANUAL_BAN: [${banType}] LOCKED [${Math.round(duration/3600000)}H] // ${manualIp}`, 'success');
    } catch (e) {
      addLog('FAILED_TO_EXECUTE_BAN', 'warn');
    }
  };

  const toggleMaintenanceMode = async () => {
    try {
      const resp = await fetch('/api/admin/maintenance', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          code: sessionStorage.getItem('alzaabi_admin_auth_code') || adminCodeInput, 
          enabled: !isMaintenance 
        })
      });
      const data = await resp.json();
      if (data.success) {
        setIsMaintenance(data.maintenance);
        addLog(`SYSTEM: MAINTENANCE_MODE_${data.maintenance ? 'ENABLED' : 'DISABLED'}`, 'warn');
      }
    } catch (e) {
      addLog('MAINTENANCE_TOGGLE_FAILED', 'warn');
    }
  };

  useEffect(() => {
    // Log Session Start
    const logSession = async () => {
      await logSecurityEvent('SESSION_START', 'User initiated neural link session', true);
    };
    logSession();

    const timer = setTimeout(() => setIsV2Ready(true), 2000);
    
    // Dynamic Title Logic
    const titles = ['ALZAABI // V2.0', 'KERNEL_SYNC_77%', 'FIREWALL_READY', 'LOGIC_DECOMPILER'];
    let count = 0;
    const titleInterval = setInterval(() => {
      document.title = titles[count % titles.length];
      count++;
    }, 3000);

    return () => {
      clearTimeout(timer);
      clearInterval(titleInterval);
    };
  }, []);

  const handleVaultArchive = async () => {
    if (!output?.content) return;
    setStatus('SYNCING_TO_VAULT...');
    addLog('Syncing to secure vault...', 'info');
    try {
      await addDoc(collection(db, 'vault'), {
        content: output.content,
        timestamp: serverTimestamp(),
        obfs: selectedObfs,
        analysis: aiAnalysis,
        uid: uid
      });
      addLog('Archive successful', 'success');
      setStatus('VAULT_SYNCED');
    } catch (error) {
      addLog('Sync failed: Persistence error', 'warn');
      setStatus('SYNC_FAILED');
    }
  };

  const updateCodeStats = (code: string) => {
    const lines = code.split('\n').length;
    const chars = code.length;
    const complexity = Math.min(Math.floor(lines / 10), 100);
    const density = Math.min(Math.floor(chars / 100), 100);
    const entropy = Math.min(Math.floor((chars / lines) * 2), 100);
    setStats({ complexity, density, entropy });
  };

  const handleNormalize = async () => {
    if (!output?.content) return;
    setIsNormalizing(true);
    setStatus('HUMANIZING_VARIABLES...');
    setAiAnalysis(null);
    addLog('Analyzing variable dependencies...', 'info');
    
    try {
      setAiAnalysis(''); 
      await normalizeVariablesStream(output.content, (chunk) => {
        setPendingAiContent(chunk);
      });
      addLog('Normalization sync complete', 'success');
      setStatus('PROCESS_COMPLETE');
      setActiveTab('ANALYSIS');
    } catch (error: any) {
      addLog('Normalization parity error', 'warn');
      setAiAnalysis(error?.message || 'LOGIC_RECOVERY_ERROR');
      setStatus('SYSTEM_ERR');
    } finally {
      setIsNormalizing(false);
    }
  };

  const handleScanVulnerabilities = async () => {
    if (!output?.content) return;
    setIsScanningVulnerabilities(true);
    setStatus('SCANNING_VULNERABILITIES...');
    setAiAnalysis(null);
    addLog('Scanning for security flaws...', 'warn');
    
    try {
      setAiAnalysis(''); 
      await scanVulnerabilitiesStream(output.content, (chunk) => {
        setPendingAiContent(chunk);
      });
      addLog('Security scan complete', 'success');
      setStatus('SCAN_COMPLETE');
      setActiveTab('ANALYSIS');
    } catch (error: any) {
      addLog('Scan failure', 'warn');
      setAiAnalysis(error?.message || 'SCAN_INTERRUPTED');
      setStatus('SYSTEM_ERR');
    } finally {
      setIsScanningVulnerabilities(false);
    }
  };

  useEffect(() => {
    // Re-check just in case, though initialized by function
    const authorized = validateEnvironment();
    setIsAuthorized(authorized);
    if (!authorized) return;

    // Show Security Intel on start
    const loadIntel = async () => {
      const intel = await getVisitorIntel();
      setVisitorIntel(intel);
    };
    loadIntel();

    const isFormInput = (el: HTMLElement | null) => {
      if (!el) return false;
      const tag = el.tagName.toLowerCase();
      return tag === 'input' || tag === 'textarea' || el.isContentEditable;
    };

    const handleContextMenu = (e: MouseEvent) => {
      if (isFormInput(e.target as HTMLElement)) return;
      e.preventDefault();
      addLog('SEC_NOTICE: BLOCK_CM', 'info');
      logSecurityEvent('RIGHT_CLICK_INTERCEPT', 'User attempted to open context menu.');
    };
    
    const handleKeyDown = (e: KeyboardEvent) => {
      // Prevent F12 or Cmd+Option+I etc.
      const isF12 = e.key === 'F12';
      
      // Ctrl+Shift+I / J / C / K / E, or Cmd equivalents on MacOS
      const isDevShortcut = 
        ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I', 'J', 'C', 'K', 'E'].includes(e.key.toUpperCase())) ||
        ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'u'); // View Source
        
      const isSavePrint = 
        (e.ctrlKey || e.metaKey) && ['S', 'P'].includes(e.key.toUpperCase()); // Save / Print

      // Copy/Cut attempts outside input fields
      const isCopyCutShortcut = 
        (e.ctrlKey || e.metaKey) && ['C', 'X'].includes(e.key.toUpperCase()) && !isFormInput(document.activeElement as HTMLElement);

      if (isF12 || isDevShortcut || isSavePrint || isCopyCutShortcut) {
        e.preventDefault();
        e.stopPropagation();
        
        let eventType = 'TAMPER_KEY_COMBO';
        let detail = `Key combo: ${(e.ctrlKey || e.metaKey) ? 'Ctrl/Cmd+' : ''}${e.shiftKey ? 'Shift+' : ''}${e.key}`;
        
        if (isF12) {
          eventType = 'F12_KEY_BLOCK';
          detail = 'User pressed F12 Key to open Developer Tools.';
        } else if (isDevShortcut) {
          eventType = 'DEVTOOLS_SHORTCUT_BLOCK';
          detail = `Developer tools shortcut combo triggered: ${e.key}`;
        } else if (isSavePrint) {
          eventType = 'SAVE_PRINT_PREVENTION';
          detail = `Attempted to save or print page: ${e.key}`;
        } else if (isCopyCutShortcut) {
          eventType = 'COPY_SHORTCUT_BLOCK';
          detail = 'Attempted to copy site content using keyboard shortcut.';
        }

        addLog(`SEC_VIOLATION: ${eventType}`, 'warn');
        logSecurityEvent(eventType, detail);
        
        if (isF12 || isDevShortcut) {
          triggerLockout(`${eventType}: ${e.key}`);
        }
      }
    };

    const handleCopy = (e: ClipboardEvent) => {
      if (isFormInput(document.activeElement as HTMLElement)) return;
      e.preventDefault();
      addLog('SEC_WARN: COPY_PREVENTED', 'warn');
      logSecurityEvent('COPY_ATTEMPT', 'User tried to copy site content.');
      triggerLockout('COPY_ATTEMPT');
    };

    const handleSelect = (e: Event) => {
      if (isFormInput(e.target as HTMLElement)) return;
      e.preventDefault();
    };

    window.addEventListener('contextmenu', handleContextMenu);
    window.addEventListener('keydown', handleKeyDown);
    window.addEventListener('copy', handleCopy);
    window.addEventListener('selectstart', handleSelect);
    
    // Advanced Security Traps
    detectDevTools(() => {
      addLog('SEC_PROBE: DEBUGGER_TOOLS_DETECTED', 'warn');
      logSecurityEvent('DEVTOOLS_SUSPICION', 'Possible inspector window detected.');
    });

    monitorPerformance(() => {
      addLog('SEC_WARN: EXECUTION_DELAY_DETECTED', 'warn');
      logSecurityEvent('PERFORMANCE_ANOMALY', 'Execution lag detected. Possible debugging/probing attempt.');
    });

    // Prevent Drag and Drop
    const handleDrag = (e: DragEvent) => {
      if (isFormInput(e.target as HTMLElement)) return;
      e.preventDefault();
    };
    window.addEventListener('dragstart', handleDrag);
    window.addEventListener('drop', handleDrag);

    addLog('NEURAL_FIREWALL_LOADED: V5.0_MAX_SEC', 'success');

    // Run Anti-Debug in background (Slower to prevent excessive CPU usage)
    const debugInterval = setInterval(() => {
      // Minimal check
    }, 10000);

    return () => {
      window.removeEventListener('contextmenu', handleContextMenu);
      window.removeEventListener('keydown', handleKeyDown);
      window.removeEventListener('copy', handleCopy);
      window.removeEventListener('selectstart', handleSelect);
      window.removeEventListener('dragstart', handleDrag);
      window.removeEventListener('drop', handleDrag);
      clearInterval(debugInterval);
    };
  }, []);

  // Auto-detection logic deactivated to prevent conflicts with layered deobfuscation

  const addLog = (msg: string, type: 'info' | 'warn' | 'success' = 'info') => {
    setSystemLogs(prev => [...prev.slice(-9), { msg, type }]);
  };

  const calculateSecurityScore = (foundTriggers: string[]) => {
    const weights: Record<string, number> = { 'Server': 15, 'Client': 5, 'Network': 10, 'Filesystem': 12, 'Suspicious': 20 };
    let score = 0;
    foundTriggers.forEach(t => {
      const type = t.split(':')[0] || 'Suspicious';
      score += weights[type] || 5;
    });
    return Math.min(score, 100);
  };

  const handleDeobfuscate = async () => {
    const codeInput = textRef.current?.value || '';
    if (!codeInput.trim()) {
      setStatus('يرجى إدخال شيفرة برمجية أولاً');
      return;
    }
    setIsLoading(true);
    setInput(codeInput);
    setStatus('جاري فك التشفير الطبقي...');
    setAiAnalysis(null);
    setTriggers([]);
    setSecurityScore(0);
    setSystemLogs([{ msg: 'Initializing Kernel...', type: 'info' }]);
    
    try {
      let currentContent = codeInput;
      addLog('Scanning memory buffers...', 'info');
      
      for (const obf of selectedObfs) {
        addLog(`Peeling layer: ${obf}`, 'info');
        try {
          const result = await deobfuscate(obf, currentContent);
          if (result.success) {
            currentContent = result.content;
            addLog(`Layer ${obf} bypassed`, 'success');
          } else {
            addLog(`Weak link in ${obf} detected`, 'warn');
          }
        } catch (e) {
          console.warn(`Layer ${obf} failed`);
          addLog(`Failed to bypass ${obf}`, 'warn');
        }
      }

      const finalTriggers = extractTriggers(currentContent);
      setTriggers(finalTriggers);
      setSecurityScore(calculateSecurityScore(finalTriggers));
      addLog('Extraction complete. Threat lvl: ' + calculateSecurityScore(finalTriggers) + '%', 'warn');

      const finalResult: DeobfuscationResult = {
        content: currentContent,
        type: selectedObfs[selectedObfs.length - 1],
        success: true
      };
      
      setOutput(finalResult);
      setStatus('SYSTEM_RECONSTRUCTING_LOGIC...');
      addLog('Reconstructing logic flow...', 'info');

      if (currentContent.length > 30000) {
        addLog('LARGE_INPUT_DETECTED: STABILITY_WARN', 'warn');
      }

      // Start Scrambling Effect - Enhanced "Hacker" Sequence (approx 5s total)
      setIsScrambling(true);
      const chars = '01#@$%^&*<>?/';
      let scrambleTimer = 0;
      
      addLog('INITIATING_VISUAL_RECONSTRUCTION...', 'info');

      const scrambleInterval = setInterval(() => {
        // Only scramble top portion for performance, but make it look dense
        const scrambled = currentContent
          .split('\n')
          .slice(0, 40) 
          .map(line => {
            const length = Math.min(line.length, 100);
            return Array(length).fill(0).map(() => chars[Math.floor(Math.random() * chars.length)]).join('');
          })
          .join('\n');
          
        setDisplayedContent(scrambled);
        scrambleTimer += 200;

        if (scrambleTimer >= 4000) { // 4 seconds of scramble
          clearInterval(scrambleInterval);
          updateCodeStats(currentContent);
          setIsScrambling(false);
          addLog('DECRYPTION_STABILIZED', 'success');
          startTypingEffect(currentContent);
        }
      }, 200);

    } catch (error) {
      console.error(error);
      setStatus('CRITICAL_ERROR');
      addLog('KERNEL_PANIC: DECODER_CRASHED', 'warn');
    } finally {
      setIsLoading(false);
    }
  };

  const startTypingEffect = (fullText: string) => {
    let index = 0;
    // Enhanced adaptive step size for extreme performance on large files
    const step = Math.max(Math.ceil(fullText.length / 30), 50); 
    
    setDisplayedContent('');
    addLog('STREAMING_CODE_TO_BUFFER...', 'info');
    
    const typingInterval = setInterval(() => {
      index += step;
      if (index >= fullText.length) {
        setDisplayedContent(fullText);
        setStatus('PROCESS_COMPLETE');
        addLog('ACCESS_GRANTED: LOGIC_RESTORED', 'success');
        clearInterval(typingInterval);
      } else {
        // Optimized update: only update what's needed
        setDisplayedContent(fullText.slice(0, index));
      }
    }, 30); // Faster interval with larger steps
  };

  // Throttled AI analysis update to prevent main thread blocking
  const [pendingAiContent, setPendingAiContent] = useState('');
  
  useEffect(() => {
    if (!pendingAiContent) return;
    
    const timeout = setTimeout(() => {
      setAiAnalysis(pendingAiContent);
    }, 100); // 100ms throttle for UI updates during streaming
    
    return () => clearTimeout(timeout);
  }, [pendingAiContent]);

  const handleAiAnalyze = async () => {
    if (!output?.content) {
      setStatus('ERR: DECODE_FIRST');
      return;
    }
    setIsAiLoading(true);
    setAiAnalysis(null);
    setPendingAiContent('');
    setActiveTab('ANALYSIS');
    setStatus('جاري فك التشفير الكامل (دقة عالية)...');
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    try {
      setAiAnalysis('');
      
      const fullRecoveredCode = await analyzeCodeStream(output.content, input, selectedObfs.join(' + '), (chunk) => {
        setPendingAiContent(chunk);
      });
      
      // Log locally if possible or just proceed
      if (fullRecoveredCode) {
        const newTriggers = extractTriggers(fullRecoveredCode);
        if (newTriggers.length > 0) {
          setTriggers(prev => Array.from(new Set([...prev, ...newTriggers])));
        }
      }
      setStatus('ANALYSIS_COMPLETE');
    } catch (error: any) {
      console.error(error);
      const errorMsg = error?.message?.includes('خطأ') 
        ? error.message 
        : 'SYSTEM_ERROR: AI_TIMEOUT. حاول مجدداً لاحقاً أو استعمل كوداً أصغر.';
      setAiAnalysis(errorMsg);
      setStatus('AI_FAIL');
      addLog('CRITICAL_RECOVERY_FAILURE', 'warn');
    } finally {
      setIsAiLoading(false);
    }
  };

  const copyToClipboard = async (text: string, id: string = 'default') => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      if (id !== 'default') {
        setCopiedText(prev => ({ ...prev, [id]: true }));
        setTimeout(() => {
          setCopiedText(prev => ({ ...prev, [id]: false }));
        }, 2000);
      }
      setStatus('تم النسخ إلى الحافظة');
      setTimeout(() => setStatus(output ? 'اكتمل بنجاح' : 'جاهز للعمل'), 2000);
      addLog(`COPIED // ${text.substring(0, 30)}${text.length > 30 ? '...' : ''}`, 'success');
    } catch (e) {
      addLog('FAILED_TO_COPY', 'warn');
    }
  };

  const downloadFile = (text: string, filename: string) => {
    const element = document.createElement("a");
    const file = new Blob([text], {type: 'text/plain'});
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    setStatus('بدأ التحميل...');
    setTimeout(() => setStatus('أكتمل التحميل'), 2000);
  };

  const copyAiDeobfuscatedCode = () => {
    if (!aiAnalysis) return;
    const regex = /```(?:[a-zA-Z1-9\+\-]+)?\n([\s\S]*?)```/g;
    const matches = [...aiAnalysis.matchAll(regex)];
    if (matches.length > 0) {
      const codeOnly = matches.map(m => m[1]).join('\n\n');
      copyToClipboard(codeOnly, 'copy_ai_decoded');
    } else {
      copyToClipboard(aiAnalysis, 'copy_ai_decoded');
    }
  };

  const downloadAiDeobfuscatedCode = () => {
    if (!aiAnalysis) return;
    const regex = /```(?:[a-zA-Z1-9\+\-]+)?\n([\s\S]*?)```/g;
    const matches = [...aiAnalysis.matchAll(regex)];
    let codeOnly = aiAnalysis;
    if (matches.length > 0) {
      codeOnly = matches.map(m => m[1]).join('\n\n');
    }
    const ext = selectedObfs.join('_').toLowerCase().includes('py') ? 'py' : 'js';
    downloadFile(codeOnly, `decoded_code_${selectedObfs.join('_').toLowerCase() || 'source'}.${ext}`);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const content = event.target?.result as string;
        if (textRef.current) textRef.current.value = content;
        setInput(content);
        setStatus('تم رفع الملف بنجاح');
      };
      reader.readAsText(file);
    }
  };

  const reset = () => {
    if (textRef.current) textRef.current.value = '';
    setInput('');
    setOutput(null);
    setAiAnalysis(null);
    setStatus('جاهز للعمل');
  };

  if (!isAuthorized) {
    return (
      <div className="min-h-screen bg-white w-full h-full flex items-center justify-center select-none" />
    );
  }

  if (isMaintenance && !isAdminAuthenticated) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4 relative overflow-hidden" dir="rtl">

        <div className="absolute inset-x-0 top-0 h-1 bg-yellow-500 shadow-[0_0_15px_rgba(234,179,8,0.8)] animate-pulse z-50" />
        
        <motion.div 
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="max-w-2xl w-full bg-black border-2 border-yellow-500 shadow-[0_0_100px_rgba(234,179,8,0.2)] p-1 relative z-10"
        >
          <div className="border border-yellow-500/30 p-8 text-center">
            <div className="w-20 h-20 border-2 border-yellow-500 flex items-center justify-center bg-yellow-500/5 rotate-45 mx-auto mb-10">
               <Wand2 className="w-10 h-10 text-yellow-500 -rotate-45 animate-pulse" />
            </div>
            
            <h2 className="text-4xl font-black text-yellow-500 uppercase tracking-tighter leading-none mb-4">
              SYSTEM_MAINTENANCE // تحت التحديث
            </h2>
            <p className="text-yellow-500/50 text-sm font-mono uppercase tracking-[0.2em] mb-12">
              الخادم حالياً في وضع الصيانة لضمان أداء أفضل وأمان أعلى.<br/>
              سنعود قريباً جداً. شكراً لصبركم.
            </p>

            <div className="flex flex-col items-center gap-6">
              <div className="flex gap-2">
                {[...Array(5)].map((_, i) => (
                  <motion.div
                    key={i}
                    animate={{ height: [10, 30, 10] }}
                    transition={{ repeat: Infinity, duration: 1, delay: i * 0.1 }}
                    className="w-1 bg-yellow-500/40"
                  />
                ))}
              </div>
              <p className="text-[10px] text-yellow-500/30 font-black uppercase tracking-[0.5em]">
                Neural Kernel Update in Progress
              </p>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  if (status === 'ACCESS_LOCKED' || (lockoutUntil && lockoutUntil > Date.now())) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4 relative overflow-hidden" dir="rtl">

        {/* Scanline & Static Effect */}
        <div className="absolute inset-0 bg-[#000500] opacity-20 pointer-events-none z-0" />
        <div className="absolute inset-x-0 top-0 h-1 bg-[#00ff00] shadow-[0_0_15px_rgba(0,255,0,0.8)] animate-scanline z-50" />
        
        <motion.div 
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          className="max-w-3xl w-full bg-black border-2 border-[#00ff00] shadow-[0_0_100px_rgba(0,255,0,0.3)] p-1 md:p-1 relative z-10"
        >
          <div className="border border-[#00ff00]/30 p-8">
            <div className="flex flex-col md:flex-row items-center justify-between gap-6 mb-10 pb-6 border-b border-[#00ff00]/20">
              <div className="flex items-center gap-4">
                <div className="w-16 h-16 border-2 border-[#00ff00] flex items-center justify-center bg-[#00ff00]/5 rotate-45">
                   <ShieldAlert className="w-10 h-10 text-[#00ff00] -rotate-45 animate-pulse" />
                </div>
                <div className="text-right">
                  <h2 className="text-4xl font-black text-[#00ff00] uppercase tracking-tighter leading-none mb-1">
                    {lockoutUntil ? 'تحذير: تم حظر الوصول' : 'تم اكتشاف انتهاك للنظام'}
                  </h2>
                  <p className="text-[#00ff00]/50 text-[10px] font-mono uppercase tracking-[0.2em]">
                    {lockoutUntil ? 'TEMPORARY_BLOCK_ACTIVE // ALZAABI_SHIELD' : 'UNAUTHORIZED ACCESS ATTEMPT LOGGED // ALZAABI_SHIELD'}
                  </p>
                </div>
              </div>
              <div className="text-[#00ff00]/20 hidden md:block">
                <Activity className="w-12 h-12" />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
              <div className="space-y-6">
                <div className="group relative">
                  <div className="absolute -inset-1 bg-gradient-to-r from-[#00ff00]/0 via-[#00ff00]/10 to-[#00ff00]/0 opacity-50" />
                  <div className="relative bg-[#00ff00]/5 border border-[#00ff00]/30 p-5 backdrop-blur-sm">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-[10px] text-[#00ff00]/40 uppercase font-bold tracking-widest text-right">TARGET_INTEL</span>
                    </div>
                    <div className="space-y-2 text-right">
                      <div className="flex justify-between items-center border-b border-[#00ff00]/10 pb-1">
                        <div className="flex items-center gap-2">
                          {visitorIntel?.ip && (
                            <button
                              onClick={() => copyToClipboard(visitorIntel.ip, 'target_intel_ip')}
                              className="px-1.5 py-0.5 border border-[#00ff00]/20 hover:border-[#00ff00]/60 bg-[#00ff00]/5 hover:bg-[#00ff00]/10 text-[#00ff00] transition-colors rounded-[2px] text-[9px] font-mono flex items-center gap-1"
                              title="نسخ عنوان IP"
                            >
                              {copiedText['target_intel_ip'] ? <span className="text-[8px] text-green-400">تم النسخ</span> : <Copy className="w-2.5 h-2.5" />}
                            </button>
                          )}
                          <span className="font-mono text-xs text-[#00ff00]">{visitorIntel?.ip || 'SCANNING...'}</span>
                        </div>
                        <span className="text-[8px] text-[#00ff00]/30 uppercase">IP_ADDR</span>
                      </div>
                      <div className="flex justify-between items-center border-b border-[#00ff00]/10 pb-1">
                        <span className="font-mono text-xs text-[#00ff00] truncate max-w-[150px]">{visitorIntel?.location || 'SEARCHING...'}</span>
                        <span className="text-[8px] text-[#00ff00]/30 uppercase">GEOLOC</span>
                      </div>
                      <div className="flex justify-between items-center bg-[#00ff00]/10 p-2 mt-4">
                        <span className="text-[10px] font-black text-[#00ff00] uppercase">
                          {lockoutUntil ? `BAN_EXPIRY: ${timeLeft}` : 'THREAT_LEVEL: CRITICAL'}
                        </span>
                        <ShieldAlert className="w-3 h-3 text-[#00ff00]" />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="bg-[#00ff00]/5 border border-[#00ff00]/30 p-5 text-right">
                  <div className="flex justify-between items-center mb-3">
                    <span className="text-[10px] text-[#00ff00]/40 uppercase font-bold tracking-widest">VIOLATION_TYPE</span>
                  </div>
                  <div className="font-mono text-sm text-[#00ff00] bg-[#00ff00]/10 p-3 border-r-4 border-[#00ff00]">
                    {lockoutUntil ? `VIOLATION: ${lockoutReason}` : status === 'ACCESS_LOCKED' ? 'TAMPER_BUFFER_PROBE' : 'UNAUTHORIZED_DOMAIN_CLONE'}
                  </div>
                </div>
              </div>

              <div className="relative aspect-square border-2 border-[#00ff00]/40 bg-black group overflow-hidden shadow-[inset_0_0_30px_rgba(0,255,0,0.2)]">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(0,255,0,0.1)_0%,transparent_100%)] z-10" />
                <div className="absolute inset-0 flex items-center justify-center z-20">
                  <div className="relative">
                    <Radar className="w-24 h-24 text-[#00ff00]/20 animate-spin" />
                    <div className="absolute inset-0 m-auto w-32 h-32 border border-[#00ff00]/10 rounded-full animate-ping" />
                    <div className="absolute inset-0 m-auto w-1 h-32 bg-[#00ff00]/20 animate-scanline" />
                  </div>
                </div>
                
                <img 
                  src={`https://static-maps.yandex.ru/1.x/?ll=${visitorIntel?.coords?.lon || 46.6753},${visitorIntel?.coords?.lat || 24.7136}&size=450,450&z=13&l=sat`} 
                  alt="Satellite Observation" 
                  className="w-full h-full object-cover opacity-60 grayscale brightness-75 contrast-150 saturate-[200%] hue-rotate-[140deg]"
                  referrerPolicy="no-referrer"
                />
                
                <div className="absolute top-2 right-2 px-2 py-1 bg-black border border-[#00ff00]/50 text-[7px] text-[#00ff00] font-bold z-40">
                  SATELLITE_UPLINK: ACTIVE
                </div>
                <div className="absolute bottom-2 left-2 flex flex-col items-start z-40 bg-black/80 p-2 border border-[#00ff00]/20">
                  <span className="text-[9px] font-mono text-[#00ff00]">{visitorIntel?.coords?.lat?.toFixed(4) || '24.7136'}, {visitorIntel?.coords?.lon?.toFixed(4) || '46.6753'}</span>
                  <span className="text-[6px] text-[#00ff00]/40 uppercase">LIVE_PULSE_LOCK</span>
                </div>
              </div>
            </div>

            <button 
              onClick={() => {
                if (lockoutUntil && lockoutUntil > Date.now()) return;
                // If it was just a local tamper, we can try to reset
                if (status === 'ACCESS_LOCKED') {
                  const authorized = validateEnvironment();
                  setIsAuthorized(authorized);
                } else {
                  window.location.reload();
                }
              }}
              disabled={lockoutUntil !== null && lockoutUntil > Date.now()}
              className="w-full py-5 bg-[#00ff00] disabled:opacity-20 text-black font-black text-xl uppercase tracking-[0.3em] hover:bg-[#00ff00]/80 transition-all shadow-[0_0_30px_rgba(0,255,0,0.4)] group overflow-hidden relative"
            >
              <span className="relative z-10">
                {lockoutUntil ? `BANNED: ${timeLeft}` : 'ACKNOWLEDGE & CLEAR BUFFER'}
              </span>
              <div className="absolute inset-0 bg-white/10 -translate-x-full group-hover:translate-x-full transition-transform duration-700 ease-in-out" />
            </button>
          </div>
        </motion.div>

        {/* Backdrop Text */}
        <div className="fixed inset-0 pointer-events-none overflow-hidden opacity-[0.03] text-[#00ff00] font-black text-[20vw] leading-none uppercase select-none z-0">
          SEC Violation SEC Violation SEC Violation SEC Violation SEC Violation
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] text-[#00ff00] font-sans selection:none user-select-none game-hud">
      {/* V2 UI HUD Overlay */}
      <div className="fixed inset-0 pointer-events-none z-50">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-[#00ff00]/10 animate-scanline" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(0,255,0,0.02)_0%,transparent_100%)]" />
      </div>

      <div className={`fixed inset-0 bg-black z-[100] flex items-center justify-center transition-opacity duration-1000 ${isV2Ready ? 'opacity-0 pointer-events-none' : 'opacity-100'}`}>
        <div className="text-[#00ff00] font-mono text-xl animate-pulse">
          INITIALIZING_ALZAABI_V2.0...
          <div className="mt-4 h-1 w-64 bg-[#00ff00]/10 overflow-hidden">
            <motion.div 
              initial={{ x: '-100%' }}
              animate={{ x: '100%' }}
              transition={{ repeat: Infinity, duration: 1 }}
              className="h-full w-full bg-[#00ff00]"
            />
          </div>
        </div>
      </div>
      
      <style dangerouslySetInnerHTML={{ __html: `
        .user-select-none {
          -webkit-user-select: none;
          -moz-user-select: none;
          -ms-user-select: none;
          user-select: none;
        }
      `}} />

      {/* Security Alert Overlay (Anti-Tamper) */}
      <AnimatePresence>
        {status === 'ACCESS_LOCKED' && (
          <motion.div 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="fixed inset-0 z-[200] bg-[#001100]/90 backdrop-blur-xl flex items-center justify-center p-6"
          >
            <div className="max-w-2xl w-full bg-black border-2 border-[#00ff00] shadow-[0_0_100px_rgba(0,255,0,0.4)] p-8 relative overflow-hidden">
               <div className="absolute top-0 left-0 w-full h-1 bg-[#00ff00] animate-pulse" />
               <div className="flex items-center gap-4 mb-8">
                  <ShieldAlert className="w-12 h-12 text-[#00ff00] animate-bounce" />
                  <div>
                    <h2 className="text-3xl font-black text-[#00ff00] uppercase tracking-tighter">System Violation Detected</h2>
                    <p className="text-[#00ff00]/60 text-xs font-mono uppercase tracking-widest">Unauthorized Access Attempt Logged</p>
                  </div>
               </div>

               <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                  <div className="space-y-4">
                     <div className="p-4 bg-[#00ff00]/10 border border-[#00ff00]/20">
                        <p className="text-[10px] text-[#00ff00]/40 uppercase mb-1">Target Intel</p>
                        <p className="font-mono text-sm text-[#00ff00] flex items-center gap-2">
                          IP: {visitorIntel?.ip || 'SCANNING...'}
                          {visitorIntel?.ip && (
                            <button
                              onClick={() => copyToClipboard(visitorIntel.ip, 'barrier_ip')}
                              className="px-1 py-0.5 border border-[#00ff00]/20 hover:border-[#00ff00]/60 bg-[#00ff00]/5 text-[#00ff00] transition-colors rounded-[2px] text-[8px] font-mono cursor-pointer"
                            >
                              {copiedText['barrier_ip'] ? '✅' : 'نسخ'}
                            </button>
                          )}
                        </p>
                        <p className="font-mono text-sm text-[#00ff00]">LOC: {visitorIntel?.location?.toUpperCase() || 'SEARCHING...'}</p>
                     </div>
                     <div className="p-4 bg-[#00ff00]/10 border border-[#00ff00]/20">
                        <p className="text-[10px] text-[#00ff00]/40 uppercase mb-1">Violation_Type</p>
                        <p className="font-mono text-sm text-[#00ff00]">TAMPER_BUFFER_PROBE</p>
                     </div>
                  </div>
                  <div className="relative aspect-square border border-[#00ff00]/40 bg-[#00ff00]/5 group overflow-hidden">
                     <div className="absolute inset-0 bg-[#00ff00]/5 animate-pulse z-10" />
                     <div className="absolute inset-0 flex items-center justify-center z-20">
                        <Radar className="w-16 h-16 text-[#00ff00]/20 animate-spin" />
                        <div className="absolute w-32 h-32 border border-[#00ff00]/10 rounded-full animate-ping" />
                     </div>
                     <img 
                       src="https://images.unsplash.com/photo-1451181502392-445000000000?q=80&w=1000&auto=format&fit=crop" 
                       alt="Satellite" 
                       className="w-full h-full object-cover opacity-30 grayscale sepia hue-rotate-[100deg] contrast-200 group-hover:scale-125 transition-transform duration-[20s]"
                     />
                     {/* Target HUD */}
                     <div className="absolute inset-0 border-[20px] border-transparent border-t-[#00ff00]/20 border-l-[#00ff00]/20 z-30" />
                     <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-12 h-12 border border-[#00ff00]/40 rounded-full z-30" />
                     <div className="absolute top-0 left-0 w-full h-[2px] bg-[#00ff00]/40 animate-scanline z-30" />
                     <div className="absolute bottom-2 left-2 text-[8px] text-[#00ff00] font-black uppercase z-40 bg-black/80 px-1 border border-[#00ff00]/20">Satellite_Uplink: Active</div>
                  </div>
               </div>

               <button 
                 onClick={() => setStatus('SYSTEM_READY')}
                 className="w-full py-4 bg-[#00ff00] text-black font-black uppercase tracking-widest hover:bg-[#00ff00]/80 transition-all"
               >
                 Acknowledge & Clear Buffer
               </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <CustomCursor />
      <BackgroundMusic />
      {/* Game HUD Frame */}
      <div className="fixed inset-0 border-[10px] border-[#00ff00]/10 pointer-events-none z-[60] flex items-center justify-center">
        <a 
          href="https://discord.com/invite/uuuu" 
          target="_blank" 
          rel="noopener noreferrer"
          className="absolute top-0 left-1/2 -translate-x-1/2 px-10 py-2 border-x border-b border-[#00ff00]/20 bg-[#050505] terminal-title text-[10px] tracking-widest text-[#00ff00]/60 pointer-events-auto hover:text-[#00ff00] hover:bg-[#00ff00]/5 transition-all cursor-pointer"
        >
          By Alzaabi Team
        </a>
      </div>

      {/* Admin Custom Broadcast Announcement */}
      {adminAlertEnabled && adminAlertMessage && (
        <div className={`border-b ${
          adminAlertType === 'RED' ? 'bg-red-950/50 border-red-500/50 text-red-400' :
          adminAlertType === 'YELLOW' ? 'bg-yellow-950/50 border-yellow-500/50 text-yellow-500' :
          'bg-green-950/50 border-green-500/30 text-[#00ff00]'
        } px-8 py-3.5 relative z-[75] backdrop-blur-md flex items-center justify-between gap-4 text-xs font-bold leading-relaxed`}>
          <div className="flex items-center gap-2 flex-row-reverse w-full justify-center text-center animate-pulse">
            <span className="text-sm">⚠️</span>
            <span className="font-sans text-right tracking-wide text-sm">{adminAlertMessage}</span>
            <span className="text-sm">⚠️</span>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="border-b border-[#00ff00]/20 bg-[#050505]/80 backdrop-blur-md sticky top-0 z-50 px-8 py-4 flex items-center justify-between overflow-hidden">
        <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#00ff00]/40 to-transparent" />
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 border-2 border-[#00ff00] flex items-center justify-center shadow-[0_0_15px_rgba(0,255,0,0.3)] group">
            <Activity className="text-[#00ff00] w-7 h-7 group-hover:scale-110 transition-transform" />
          </div>
          <div>
            <h1 className="text-2xl font-bold terminal-title uppercase flex items-center gap-2">
              ALZAABI <span className="text-[10px] bg-[#00ff00] text-black px-1 rounded-sm animate-pulse">V2.0</span>
            </h1>
            <p className="text-[10px] uppercase tracking-widest text-[#00ff00]/50">Advanced Quantum Logic Reconstruction</p>
          </div>
        </div>

        <div className="flex items-center gap-6">
          <div className="hidden md:flex items-center gap-4 bg-black/40 border border-[#00ff00]/10 px-3 py-1.5 rounded-sm">
            <div className="flex flex-col">
              <span className="text-[6px] text-[#00ff00]/40 uppercase font-black">CPU_Core_Delta</span>
              <div className="flex items-center gap-1">
                {[1,2,3,4,5,6].map(i => (
                  <motion.div 
                    key={i}
                    animate={{ height: [2, Math.random() * 8 + 2, 2] }}
                    transition={{ repeat: Infinity, duration: Math.random() * 0.5 + 0.5 }}
                    className="w-[2px] bg-[#00ff00]/60"
                  />
                ))}
              </div>
            </div>
            <div className="h-6 w-[1px] bg-[#00ff00]/10" />
            <div className="flex flex-col">
              <span className="text-[6px] text-[#00ff00]/40 uppercase font-black">Link_Stability</span>
              <span className="text-[10px] font-mono font-black text-[#00ff00]">99.98%</span>
            </div>
          </div>

          <div className="flex flex-col items-end border-r border-[#00ff00]/20 pr-4">
            <span className="text-[8px] opacity-40 uppercase tracking-widest font-mono">Kernel_Status</span>
            <div className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full ${isLoading || isAiLoading ? 'bg-yellow-400 shadow-[0_0_10px_#facc15]' : 'bg-[#00ff00] shadow-[0_0_10px_#00ff00]'}`} />
              <span className="text-[10px] font-mono text-[#00ff00] font-black">{status}</span>
            </div>
          </div>
          <div className="flex items-center gap-4">
             <div className="flex items-center gap-2 px-3 py-1 border border-[#00ff00]/30 bg-[#00ff00]/5">
                <ShieldCheck className="w-4 h-4 text-[#00ff00]" />
                <span className="text-[10px] font-black uppercase tracking-tighter text-[#00ff00]">Neural Firewall Active</span>
             </div>
             <button 
               onClick={() => setIsIntelOpen(true)}
               className="text-[#00ff00]/60 hover:text-[#00ff00] transition-colors flex flex-col items-center gap-1 group"
             >
                <Activity className="w-5 h-5 group-hover:scale-110 transition-transform" />
                <span className="text-[8px] uppercase font-black">Security Intel</span>
             </button>
             <a 
               href="https://discord.com/invite/uuuu" 
               target="_blank" 
               rel="noopener noreferrer"
               className="text-[#00ff00]/60 hover:text-[#00ff00] transition-colors flex flex-col items-center gap-1 group"
             >
                <MessageSquare className="w-5 h-5 group-hover:scale-110 transition-transform" />
                <span className="text-[8px] uppercase font-black">Discord</span>
             </a>
          </div>
        </div>
      </header>

      {/* Security Intel Modal */}
      <AnimatePresence>
        {isIntelOpen && visitorIntel && (
          <div className="fixed inset-0 z-[150] flex items-center justify-center p-4">
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsIntelOpen(false)}
              className="absolute inset-0 bg-black/90 backdrop-blur-xl"
            />
            <motion.div 
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="relative w-full max-w-2xl bg-black border border-[#00ff00]/30 shadow-[0_0_50px_rgba(0,255,0,0.2)] p-8 overflow-hidden"
            >
               <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-[#00ff00] to-transparent animate-pulse" />
               
               <div className="flex items-center justify-between mb-8">
                  <div className="flex items-center gap-4">
                     <Radar className="w-10 h-10 text-[#00ff00] animate-spin" />
                     <div>
                        <h2 className="text-2xl font-black uppercase tracking-tighter">Visitor_Intelligence_Sync</h2>
                        <p className="text-[10px] text-[#00ff00]/40 uppercase font-mono tracking-widest">Real-time meta-data extraction</p>
                     </div>
                  </div>
                  <button onClick={() => setIsIntelOpen(false)} className="text-[#00ff00]/40 hover:text-[#00ff00]">
                    <X className="w-6 h-6" />
                  </button>
               </div>

               <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
                  <div className="space-y-4">
                     <div className="p-4 bg-[#00ff00]/5 border border-[#00ff00]/10 flex items-start gap-4">
                        <Radio className="w-5 h-5 text-[#00ff00] mt-1" />
                        <div>
                           <p className="text-[9px] text-[#00ff00]/40 uppercase mb-1">Network_Identity</p>
                           <p className="font-mono text-xs text-[#00ff00] flex items-center gap-2">
                             <span className="opacity-40">IP:</span> {visitorIntel.ip}
                             <button
                               onClick={() => copyToClipboard(visitorIntel.ip, 'modal_ip')}
                               className="px-1.5 py-0.5 border border-[#00ff00]/20 hover:border-[#00ff00]/60 bg-[#00ff00]/5 text-[#00ff00] transition-colors rounded-[2px] text-[8px] font-mono cursor-pointer"
                             >
                               {copiedText['modal_ip'] ? '✅ تم النسخ' : 'نسخ IP'}
                             </button>
                           </p>
                           <p className="font-mono text-xs text-[#00ff00] leading-tight mt-1"><span className="opacity-40">ISP:</span> {visitorIntel.network}</p>
                           <p className="font-mono text-[9px] text-[#00ff00]/60 uppercase mt-2">ASN: {visitorIntel.asn}</p>
                           <div className="flex items-center gap-4 mt-2">
                              <div className="flex items-center gap-1">
                                 <Wifi className="w-3 h-3 text-[#00ff00]/40" />
                                 <span className="text-[9px] font-mono text-[#00ff00]/60">{visitorIntel.client.connection}</span>
                              </div>
                           </div>
                        </div>
                     </div>
                     <div className="p-4 bg-[#00ff00]/5 border border-[#00ff00]/10 flex items-start gap-4">
                        <Globe className="w-5 h-5 text-[#00ff00] mt-1" />
                        <div>
                           <p className="text-[9px] text-[#00ff00]/40 uppercase mb-1">Geospatial_Loc</p>
                           <p className="font-mono text-xs text-[#00ff00]">{visitorIntel.location}</p>
                           <div className="grid grid-cols-2 gap-4 mt-2">
                              <div>
                                 <p className="text-[8px] opacity-40 uppercase">Timezone</p>
                                 <p className="text-[9px] text-[#00ff00]/60 font-mono">{visitorIntel.timezone}</p>
                              </div>
                              <div>
                                 <p className="text-[8px] opacity-40 uppercase">Currency</p>
                                 <p className="text-[9px] text-[#00ff00]/60 font-mono">{visitorIntel.currency}</p>
                              </div>
                           </div>
                        </div>
                     </div>
                     <div className="p-4 bg-[#00ff00]/5 border border-[#00ff00]/10 flex items-start gap-4">
                        <Battery className="w-5 h-5 text-[#00ff00] mt-1" />
                        <div>
                           <p className="text-[9px] text-[#00ff00]/40 uppercase mb-1">Power_Matrix</p>
                           <p className="font-mono text-xs text-[#00ff00] uppercase">{visitorIntel.client.battery}</p>
                        </div>
                     </div>
                  </div>
                  <div className="space-y-4">
                     <div className="p-4 bg-[#00ff00]/5 border border-[#00ff00]/10 flex items-start gap-4">
                        <Monitor className="w-5 h-5 text-[#00ff00] mt-1" />
                        <div>
                           <p className="text-[9px] text-[#00ff00]/40 uppercase mb-1">Hardware_Profile</p>
                           <div className="grid grid-cols-2 gap-x-6 gap-y-2">
                              <div>
                                 <p className="text-[8px] opacity-40 uppercase">Cores</p>
                                 <p className="text-[10px] text-[#00ff00] font-mono">{visitorIntel.client.cores} CPU</p>
                              </div>
                              <div>
                                 <p className="text-[8px] opacity-40 uppercase">Memory</p>
                                 <p className="text-[10px] text-[#00ff00] font-mono">{visitorIntel.client.memory}</p>
                              </div>
                              <div>
                                 <p className="text-[8px] opacity-40 uppercase">Display</p>
                                 <p className="text-[10px] text-[#00ff00] font-mono">{visitorIntel.client.screen}</p>
                              </div>
                              <div>
                                 <p className="text-[8px] opacity-40 uppercase">Platform</p>
                                 <p className="text-[10px] text-[#00ff00] font-mono">{visitorIntel.client.platform}</p>
                              </div>
                           </div>
                        </div>
                     </div>
                     <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                        <div className="p-3 bg-white/5 border border-white/10 flex flex-col gap-1">
                           <span className="text-[8px] text-[#00ff00]/40 uppercase font-black flex items-center gap-1"><Monitor className="w-2 h-2"/> Platform</span>
                           <span className="text-xs font-mono text-white/80">{visitorIntel.client.platform}</span>
                        </div>
                        <div className="p-3 bg-white/5 border border-white/10 flex flex-col gap-1">
                           <span className="text-[8px] text-[#00ff00]/40 uppercase font-black flex items-center gap-1"><Cpu className="w-2 h-2"/> Cores / Mem</span>
                           <span className="text-xs font-mono text-white/80">{visitorIntel.client.cores} Cores / {visitorIntel.client.memory}</span>
                        </div>
                        <div className="p-3 bg-white/5 border border-white/10 flex flex-col gap-1">
                           <span className="text-[8px] text-[#00ff00]/40 uppercase font-black flex items-center gap-1"><Wifi className="w-2 h-2"/> Conn_Hub</span>
                           <span className="text-xs font-mono text-white/80">{visitorIntel.client.connection}</span>
                        </div>
                        <div className="p-3 bg-white/5 border border-white/10 flex flex-col gap-1">
                           <span className="text-[8px] text-[#00ff00]/40 uppercase font-black flex items-center gap-1"><Battery className="w-2 h-2"/> Energy_Cell</span>
                           <span className="text-xs font-mono text-white/80">{visitorIntel.client.battery}</span>
                        </div>
                     </div>

                     <div className="relative aspect-video border border-[#00ff00]/20 overflow-hidden bg-black/50 group">
                        {/* Scanning Effect */}
                        <div className="absolute inset-0 bg-gradient-to-b from-[#00ff00]/10 to-transparent h-1/2 w-full animate-pulse z-30 pointer-events-none" />
                        <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
                           <div className="relative">
                             <Radar className="w-16 h-16 text-[#00ff00]/20 animate-spin" />
                             <MapPin className="absolute inset-0 m-auto w-8 h-8 text-[#00ff00] animate-bounce" />
                             <div className="absolute inset-0 m-auto w-24 h-24 border border-[#00ff00]/20 rounded-full animate-ping" />
                           </div>
                        </div>
                        
                        {visitorIntel.coords.lat && (
                           <div className="relative w-full h-full">
                              <img 
                                 src={`https://static-maps.yandex.ru/1.x/?ll=${visitorIntel.coords.lon},${visitorIntel.coords.lat}&size=600,450&z=12&l=sat&pt=${visitorIntel.coords.lon},${visitorIntel.coords.lat},pm2rdl`}
                                 alt="Satellite Intelligence"
                                 className="w-full h-full object-cover opacity-80 grayscale contrast-125 brightness-110 sepia hue-rotate-[100deg] saturate-150 select-none group-hover:scale-110 transition-transform duration-[10s] ease-linear"
                                 referrerPolicy="no-referrer"
                              />
                              {/* Grid Overlay */}
                              <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.03),rgba(0,255,0,0.01),rgba(0,0,255,0.03))] bg-[length:100%_2px,3px_100%] pointer-events-none z-10" />
                           </div>
                        )}
                        
                        <div className="absolute top-2 left-2 px-2 py-1 bg-black/80 border border-[#00ff00]/40 text-[7px] font-black uppercase z-40 flex items-center gap-1">
                           <div className="w-1 h-1 bg-[#00ff00] rounded-full animate-pulse" />
                           LIVE_SATELLITE_UPLINK: ENCRYPTED
                        </div>
                        <div className="absolute top-2 right-2 flex flex-col items-end z-40">
                           <div className="px-2 py-1 bg-black/80 border border-[#00ff00]/40 text-[7px] font-mono text-[#00ff00]/60 uppercase">
                             ALT: 402,000M
                           </div>
                        </div>
                        <div className="absolute bottom-2 left-2 px-2 py-1 bg-black/80 border border-[#00ff00]/40 text-[8px] font-black uppercase z-40 font-mono flex flex-col">
                           <span className="text-[#00ff00]">{visitorIntel.coords.lat?.toFixed(4)}, {visitorIntel.coords.lon?.toFixed(4)}</span>
                           <span className="text-[6px] opacity-40">LOCK_STABLE_V2</span>
                        </div>
                     </div>
                  </div>
               </div>

               <div className="p-4 border border-yellow-500/30 bg-yellow-500/5 flex items-start gap-3">
                  <ShieldAlert className="w-5 h-5 text-yellow-500 shrink-0 mt-0.5" />
                  <p className="text-[11px] text-yellow-500 leading-relaxed font-medium uppercase font-mono">
                     Note: This information is extracted via Neural Firewall logic. Your meta-data is currently being synchronized with our security database to ensure protection against unauthorized re-obfuscation.
                  </p>
               </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      <main className="container max-w-7xl mx-auto p-4 lg:p-6 grid grid-cols-1 lg:grid-cols-12 gap-4 lg:gap-6 pb-20">
        {/* Sidebar */}
        <aside className="lg:col-span-3 space-y-4">
          <div className="bg-black/40 border border-[#00ff00]/20 p-4 backdrop-blur-sm shadow-[0_0_20px_rgba(0,255,0,0.05)]">
            <h2 className="text-[10px] font-bold text-[#00ff00]/60 uppercase tracking-widest mb-4 flex items-center gap-2 terminal-title">
              <Cpu className="w-3 h-3" /> ALGORITHMS
            </h2>
            <nav className="space-y-1">
              {OBFS.map((obf) => {
                const isActive = selectedObfs.includes(obf);
                return (
                  <button
                    key={obf}
                    onClick={() => {
                      if (isActive && selectedObfs.length > 1) {
                        setSelectedObfs(prev => prev.filter(t => t !== obf));
                      } else if (!isActive) {
                        setSelectedObfs(prev => [...prev, obf]);
                      }
                    }}
                    className={`w-full text-right px-4 py-3 border-r-4 transition-all duration-300 flex items-center justify-between group ${
                      isActive 
                      ? 'border-[#00ff00] bg-[#00ff00]/10 text-[#00ff00] shadow-[0_0_15px_rgba(0,255,0,0.1)]' 
                      : 'border-transparent hover:border-[#00ff00]/50 text-[#00ff00]/40 hover:bg-[#00ff00]/5'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`w-3 h-3 border border-[#00ff00]/30 rounded-sm flex items-center justify-center transition-all ${isActive ? 'bg-[#00ff00]/20 border-[#00ff00]' : ''}`}>
                        {isActive && <div className="w-1.5 h-1.5 bg-[#00ff00]" />}
                      </div>
                      <div className="flex flex-col items-start pr-3">
                        <span className="font-mono text-sm tracking-tighter">{obf}</span>
                        {obf === 'Luraph' && (
                          <span className="text-[7px] opacity-40 uppercase leading-none mt-1">
                            VM / VM_STRIKE / JUNK_CLEANER / CF_REVERSE / ANTI_DEBUG
                          </span>
                        )}
                      </div>
                    </div>
                    {isActive ? <Radar className="w-3 h-3 text-[#00ff00]" /> : <ChevronRight className="w-3 h-3 opacity-0 group-hover:opacity-100" />}
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="bg-black/40 border border-[#00ff00]/20 p-4 relative overflow-hidden backdrop-blur-sm">
            <h2 className="text-[10px] font-bold text-[#00ff00]/60 uppercase tracking-widest mb-4 flex items-center gap-2 terminal-title">
              <Binary className="w-3 h-3" /> CODE_METRICS
            </h2>
            <div className="space-y-3">
              {[
                { label: 'Complexity', val: stats.complexity, color: 'bg-blue-500' },
                { label: 'Density', val: stats.density, color: 'bg-purple-500' },
                { label: 'Entropy', val: stats.entropy, color: 'bg-[#00ff00]' },
              ].map((item) => (
                <div key={item.label} className="space-y-1">
                  <div className="flex justify-between text-[8px] uppercase font-mono">
                    <span className="opacity-40">{item.label}</span>
                    <span className="text-[#00ff00]">{item.val}%</span>
                  </div>
                  <div className="h-1 w-full bg-white/5">
                    <motion.div 
                      initial={{ width: 0 }}
                      animate={{ width: `${item.val}%` }}
                      className={`h-full shadow-[0_0_5px_rgba(0,255,0,0.3)] ${item.color}`}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-black/40 border border-[#00ff00]/20 p-4 relative overflow-hidden backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-24 h-24 bg-[#00ff00]/5 -mr-12 -mt-12 rounded-full blur-2xl" />
            <h2 className="text-[10px] font-bold text-[#00ff00]/60 uppercase tracking-widest mb-4 flex items-center gap-2 terminal-title">
              <ShieldAlert className="w-3 h-3" /> THREAT_LEVEL
            </h2>
            <div className="relative pt-2">
              <div className="flex justify-between text-[10px] uppercase font-mono mb-1">
                <span>Safe</span>
                <span>Critical</span>
              </div>
              <div className="h-1.5 w-full bg-white/5 overflow-hidden">
                <motion.div 
                  initial={{ width: 0 }}
                  animate={{ width: `${securityScore}%` }}
                  className={`h-full shadow-[0_0_10px_#00ff00] ${
                    securityScore > 70 ? 'bg-[#00ff00]' : securityScore > 30 ? 'bg-yellow-500' : 'bg-[#00ff00]'
                  }`}
                />
              </div>
              <div className="mt-2 text-right">
                <span className={`text-xl font-black font-mono ${
                  securityScore > 70 ? 'text-[#00ff00]' : securityScore > 30 ? 'text-yellow-500' : 'text-[#00ff00]'
                }`}>
                  {securityScore}%
                </span>
              </div>
            </div>
          </div>

          <div className="bg-black/40 border border-white/5 p-4 backdrop-blur-sm h-48 flex flex-col">
            <h2 className="text-[10px] font-bold text-white/30 uppercase tracking-widest mb-2 flex items-center gap-2 terminal-title">
              <ListRestart className="w-3 h-3" /> SYSTEM_LOGS
            </h2>
            <div className="flex-1 overflow-auto space-y-1 pr-1 custom-scrollbar text-[9px] font-mono">
              <AnimatePresence initial={false}>
                {systemLogs.map((log, i) => (
                  <motion.div 
                    key={i}
                    initial={{ opacity: 0, x: -5 }}
                    animate={{ opacity: 1, x: 0 }}
                    className={`${
                      log.type === 'success' ? 'text-green-500' : 
                      log.type === 'warn' ? 'text-yellow-500' : 
                      'text-white/40'
                    }`}
                  >
                    <span className="mr-2">&gt;</span>
                    {log.msg}
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
          </div>

          <AnimatePresence>
            {triggers.length > 0 && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-[#00ff00]/5 border border-[#00ff00]/30 p-4 shadow-[0_0_20px_rgba(0,255,0,0.1)]"
              >
                <h2 className="text-[10px] font-bold text-[#00ff00] uppercase tracking-widest mb-3 flex items-center gap-2 terminal-title">
                  <Radio className="w-3 h-3 animate-ping" /> EXTRACTED_EVENTS
                </h2>
                <div className="space-y-4 max-h-[400px] overflow-auto pr-2 custom-scrollbar">
                  {triggers.map((trigger, idx) => {
                    // Splits on first occurrence of ": "
                    const colonIndex = trigger.indexOf(': ');
                    const [type, name] = colonIndex !== -1 
                      ? [trigger.substring(0, colonIndex), trigger.substring(colonIndex + 2)]
                      : ['Event', trigger];
                    
                    let bgClass = 'bg-[#00ff00]/10 text-[#00ff00] border-[#00ff00]/30';
                    if (type === 'TriggerEvent') {
                      bgClass = 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
                    } else if (type === 'RegisterEvent') {
                      bgClass = 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
                    } else if (type === 'ObfuscatedEvent') {
                      bgClass = 'bg-amber-500/20 text-amber-400 border-amber-500/30';
                    } else if (type === 'Base64DecodedEvent') {
                      bgClass = 'bg-purple-500/20 text-purple-400 border-purple-500/30';
                    } else if (type === 'Server') {
                      bgClass = 'bg-[#00ff00]/20 text-[#00ff00] border-[#00ff00]/30';
                    } else if (type === 'Client') {
                      bgClass = 'bg-blue-500/20 text-blue-400 border-blue-500/30';
                    } else if (type === 'Hook' || type === 'Server Hook') {
                      bgClass = 'bg-pink-500/20 text-pink-400 border-pink-500/30';
                    }

                    return (
                      <div key={idx} className="bg-black/60 p-2 border-l-2 border-[#00ff00] border-y border-r border-[#00ff00]/20 flex flex-col gap-1 group select-text">
                        <div className="flex items-center justify-between">
                          <span className={`text-[8px] font-mono font-bold px-1.5 py-0.5 rounded-[2px] border ${bgClass}`}>
                            {type}
                          </span>
                          <button 
                            onClick={() => copyToClipboard(name, `copy_trigger_${idx}`)}
                            className="text-[8px] text-[#00ff00]/50 hover:text-[#00ff00] uppercase font-mono cursor-pointer"
                          >
                            {copiedText[`copy_trigger_${idx}`] ? 'تم النسخ!' : 'نسخ اسم التريجر'}
                          </button>
                        </div>
                        <code className="text-[10px] font-mono text-green-100 break-all leading-tight">{name}</code>
                      </div>
                    );
                  })}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
          <div className="bg-black/40 border border-[#00ff00]/20 p-4 backdrop-blur-sm">
            <h2 className="text-[10px] font-bold text-[#00ff00]/60 uppercase tracking-widest mb-3 flex items-center gap-2 terminal-title">
              <Database className="w-3 h-3" /> SEC_VAULT
            </h2>
            <button 
              onClick={handleVaultArchive}
              disabled={!displayedContent}
              className="w-full py-2 border border-[#00ff00]/20 text-[9px] uppercase font-bold text-[#00ff00]/40 hover:bg-[#00ff00]/5 transition-all disabled:opacity-20"
            >
              Sync to Vault
            </button>
          </div>
        </aside>

        {/* Content Area */}
        <div className="lg:col-span-9 space-y-6">
          {/* Workspace Tabs */}
          <div className="flex items-center gap-2 border-b border-[#00ff00]/20 bg-black/40 p-1 backdrop-blur-md">
            {[
              { id: 'SOURCE', label: 'المصدر (Source)', icon: FileCode2 },
              { id: 'ANALYSIS', label: 'الفك بالذكاء (Full Decode)', icon: BrainCircuit },
              { id: 'LOGS', label: 'سجلات النظام (Logs)', icon: Terminal },
              { id: 'SECURITY', label: 'إدارة الأمن (Security)', icon: ShieldCheck }
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-4 py-2 text-[10px] uppercase font-bold tracking-widest flex items-center gap-2 transition-all border-t-2 ${
                  activeTab === tab.id 
                  ? 'border-[#00ff00] bg-[#00ff00]/10 text-[#00ff00]' 
                  : 'border-transparent text-[#00ff00]/40 hover:bg-[#00ff00]/5'
                }`}
              >
                <tab.icon className="w-3 h-3" />
                {tab.label}
              </button>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {activeTab === 'SECURITY' && (
              <motion.div
                key="security-tab"
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 10 }}
                className="space-y-6"
              >
                {!isAdminAuthenticated ? (
                  <div className="bg-black/60 border border-[#00ff00]/20 p-12 flex flex-col items-center justify-center min-h-[500px] relative overflow-hidden">
                    <div className="absolute inset-0 bg-[#00ff00]/5 animate-pulse pointer-events-none" />
                    <Lock className="w-16 h-16 text-[#00ff00] mb-6 animate-bounce" />
                    <h2 className="text-2xl font-black text-[#00ff00] uppercase tracking-tighter mb-2">System Security Gate</h2>
                    <p className="text-[#00ff00]/50 text-[10px] uppercase tracking-[0.3em] mb-8 text-center">
                      Dynamic Code Encryption Active<br/>
                      <span className="text-[#00ff00] font-bold animate-pulse">SYSTEM_KEY_ROTATION: {Math.random().toString(36).substring(2, 10).toUpperCase()}</span><br/>
                      Check Discord Webhook for 30-min Rotating Key
                    </p>

                    <div className="absolute left-4 top-4 hidden lg:block overflow-hidden h-48 w-48 opacity-20 transition-opacity hover:opacity-100">
                      <div className="font-mono text-[6px] text-[#00ff00] space-y-1 animate-scroll-up">
                        {Array(20).fill(0).map((_, i) => (
                          <div key={i}>[{new Date().toLocaleTimeString()}] KERNEL_LOG_{Math.random().toString(36).substring(7).toUpperCase()}: 0x{Math.floor(Math.random()*16777215).toString(16).toUpperCase()} PROBE_{i}</div>
                        ))}
                      </div>
                    </div>

                    <div className="absolute right-4 bottom-4 hidden lg:block opacity-20">
                      <div className="w-16 h-16 border-2 border-[#00ff00]/30 animate-spin-slow flex items-center justify-center">
                        <Database className="w-6 h-6 text-[#00ff00]/30" />
                      </div>
                    </div>
                    
                    <div className="w-full max-w-sm space-y-4 relative z-10">
                      <div className="space-y-1">
                        <label className="text-[10px] text-[#00ff00]/40 uppercase font-bold text-right block">Enter Security Key</label>
                        <input 
                          type="password" 
                          value={adminCodeInput}
                          onChange={(e) => setAdminCodeInput(e.target.value)}
                          onKeyDown={(e) => e.key === 'Enter' && handleAdminLogin()}
                          placeholder="••••••••••••••••••••"
                          className="w-full bg-black border-2 border-[#00ff00]/30 p-4 text-center text-sm font-black tracking-widest text-[#00ff00] outline-none focus:border-[#00ff00] transition-colors"
                        />
                      </div>
                      
                      {loginError && (
                        <p className="text-red-500 text-[10px] uppercase font-bold text-center animate-shake">
                          Error: {loginError}
                        </p>
                      )}

                      <button 
                        onClick={handleAdminLogin}
                        disabled={isLoggingIn || !adminCodeInput}
                        className="w-full py-4 bg-[#00ff00] text-black font-black uppercase tracking-widest hover:bg-[#00ff00]/80 transition-all disabled:opacity-30 flex items-center justify-center gap-3"
                      >
                        {isLoggingIn ? <Activity className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
                        Verifying Security Key
                      </button>
                    </div>
                    
                    <div className="mt-12 text-[8px] text-[#00ff00]/20 uppercase font-mono text-center">
                      Neural Security Protocol V5.0 // (C) AI STUDIO BUILD
                    </div>
                  </div>
                ) : (
                  <div className="bg-black/60 border border-[#00ff00]/20 p-6 min-h-[800px] flex flex-col relative overflow-hidden">

                    <div className="absolute inset-0 bg-[#000500]/30 pointer-events-none" />
                    
                    <div className="flex items-center justify-between mb-8 relative z-10">
                      <div className="flex items-center gap-4">
                        <div className="w-14 h-14 border-2 border-[#00ff00] flex items-center justify-center bg-[#101510] shadow-[0_0_20px_rgba(0,255,0,0.2)]">
                          <Terminal className="w-8 h-8 text-[#00ff00]" />
                        </div>
                        <div>
                          <h2 className="text-3xl font-black text-[#00ff00] uppercase tracking-tighter">مركز تحكم الأمن // OPS_CENTER</h2>
                          <div className="flex items-center gap-4 mt-1">
                            <div className="flex items-center gap-2">
                              <div className="w-2 h-2 bg-[#00ff00] rounded-full animate-pulse shadow-[0_0_8px_#00ff00]" />
                              <span className="text-[10px] text-[#00ff00] font-black uppercase tracking-widest">Master_Console_Linked</span>
                            </div>
                            <span className="text-[10px] text-[#00ff00]/30 font-mono">ID: ALZAABI_HUB_SYS</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-8">
                        <div className="text-right hidden md:block">
                          <p className="text-[9px] text-[#00ff00]/40 uppercase font-black tracking-widest">إجمالي المحظورين</p>
                          <p className="text-lg font-black text-[#00ff00] font-mono">{globalBans.length}</p>
                        </div>
                        <button 
                          onClick={() => {
                            setIsAdminAuthenticated(false);
                            sessionStorage.removeItem('alzaabi_admin_auth');
                          }}
                          className="px-6 py-2 bg-red-500/10 border border-red-500/50 text-red-500 text-[10px] uppercase font-black hover:bg-red-500 hover:text-black transition-all shadow-[0_0_15px_rgba(239,68,68,0.2)]"
                        >
                          خروج (Terminate)
                        </button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8 relative z-10">
                      <div className="p-5 bg-black/80 border border-[#00ff00]/20 flex flex-col gap-2 group hover:border-[#00ff00]/60 transition-all backdrop-blur-md">
                        <span className="text-[10px] text-[#00ff00]/40 uppercase font-black text-right">حالة جدار الحماية</span>
                        <div className="flex items-center gap-3 text-[#00ff00] font-black text-xl justify-end">
                          <ShieldCheck className="w-6 h-6 animate-pulse" />
                          <span className="tracking-widest">Active_Neural_Guard</span>
                        </div>
                      </div>
                      <button 
                        onClick={toggleMaintenanceMode}
                        className={`p-5 border transition-all flex flex-col gap-2 text-right backdrop-blur-md ${
                          isMaintenance 
                            ? 'bg-yellow-500/10 border-yellow-500/50 text-yellow-500' 
                            : 'bg-green-500/5 border-[#00ff00]/20 text-[#00ff00]'
                        }`}
                      >
                        <span className="text-[10px] uppercase font-black">وضع الصيانة (Maintenance Protocol)</span>
                        <div className="flex items-center gap-3 font-black text-xl justify-end">
                          {isMaintenance ? <Wand2 className="w-6 h-6" /> : <Activity className="w-6 h-6" />}
                          <span className="tracking-widest">{isMaintenance ? 'LOCKDOWN_ACTIVE' : 'SYSTEM_OPEN'}</span>
                        </div>
                      </button>
                    </div>

                    {/* Three-Option Security Ban Override Hub */}
                    <div className="bg-black/80 border border-[#00ff00]/20 p-6 mb-6 relative z-10 backdrop-blur-md">
                      <h3 className="text-xs font-black text-[#00ff00] uppercase tracking-widest mb-4 flex items-center justify-between flex-row-reverse">
                         <div className="flex items-center gap-2">
                           <ShieldAlert className="w-4 h-4 text-red-500 animate-pulse" /> لوحة التحكم والحظر الذكي (Interactive Firewall Hub)
                         </div>
                         <span className="text-[9px] text-[#00ff00]/40 font-mono">SEC_OVERRIDE_V2.0</span>
                      </h3>

                      {/* Segmented controls tab */}
                      <div className="flex gap-2 border-b border-[#00ff00]/10 pb-4 mb-4 flex-row-reverse">
                        {[
                          { id: 'IP', label: 'حظر عنوان IP' },
                          { id: 'DEVICE', label: 'حظر مستخدم (بصمة المتصفح)' },
                          { id: 'UNBAN', label: 'إلغاء حظر يدوي' }
                        ].map((mode) => (
                          <button
                            key={mode.id}
                            onClick={() => {
                              setBanType(mode.id as any);
                              setManualIp('');
                            }}
                            className={`px-4 py-2 text-[10px] uppercase font-bold tracking-widest transition-all border ${
                              banType === mode.id
                              ? 'bg-red-500/10 border-red-500 text-red-400'
                              : 'border-[#00ff00]/20 text-[#00ff00]/40 hover:bg-[#00ff00]/5'
                            }`}
                          >
                            {mode.label}
                          </button>
                        ))}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="space-y-1">
                          <span className="text-[8px] text-[#00ff00]/40 uppercase font-black px-1 text-right block">
                            {banType === 'IP' && 'عنوان IP المستهدف IP_Target'}
                            {banType === 'DEVICE' && 'رمز بصمة المستخدم Device_Signature'}
                            {banType === 'UNBAN' && 'الهدف المراد إلغاء حظره IP_or_Device'}
                          </span>
                          <input 
                            type="text" 
                            value={manualIp}
                            onChange={(e) => setManualIp(e.target.value)}
                            placeholder={banType === 'IP' ? '0.0.0.0' : banType === 'DEVICE' ? 'FPR-XXXXXX' : 'أدخل الـ IP أو البصمة...'}
                            className="w-full bg-black/60 border border-[#00ff00]/30 p-3 text-sm text-[#00ff00] font-mono outline-none focus:border-[#00ff00] text-center"
                          />
                          {banType === 'DEVICE' && deviceFingerprint && (
                            <div className="text-[8px] text-yellow-500/60 font-mono text-center mt-1">
                              بصمتك الحالية المعافاة: {deviceFingerprint}
                            </div>
                          )}
                        </div>

                        {banType !== 'UNBAN' ? (
                          <>
                            <div className="space-y-1">
                              <span className="text-[8px] text-[#00ff00]/40 uppercase font-black px-1 block text-right">سبب ارتكاب المخالفة Reason</span>
                              <input 
                                type="text" 
                                value={manualReason}
                                onChange={(e) => setManualReason(e.target.value)}
                                placeholder="SUSPICIOUS_PROBE"
                                className="w-full bg-black/60 border border-[#00ff00]/30 p-3 text-sm text-[#00ff00] outline-none focus:border-[#00ff00] text-right"
                              />
                            </div>
                            <div className="space-y-1">
                              <span className="text-[8px] text-[#00ff00]/40 uppercase font-black px-1 block text-right">مدة الحظر (Duration)</span>
                              <select
                                value={manualDuration}
                                onChange={(e) => setManualDuration(e.target.value)}
                                className="w-full bg-black/60 border border-[#00ff00]/30 p-3 text-sm text-[#00ff00] outline-none focus:border-[#00ff00] text-right"
                              >
                                <option value="3600000">ساعة واحدة (1 Hour)</option>
                                <option value="43200000">12 ساعة (12 Hours)</option>
                                <option value="86400000">يوم واحد (1 Day)</option>
                                <option value="604800000">7 أيام (7 Days)</option>
                                <option value="315360000000">دائم (Permanent)</option>
                              </select>
                            </div>
                          </>
                        ) : (
                          <div className="md:col-span-2 flex items-center justify-center text-[11px] text-[#00ff00]/40 border border-[#00ff00]/10 bg-black/40 px-4 py-3 text-right">
                            سيتم حذف سجل الحظر بشكل كامل من القواعد، مما يمكن الزائر من معاودة الاتصال فوراً
                          </div>
                        )}
                      </div>

                      <div className="mt-4 flex justify-end">
                        <button 
                          onClick={handleManualBan}
                          className={`px-8 h-[46px] border text-xs font-black uppercase tracking-widest transition-all ${
                            banType === 'UNBAN'
                            ? 'bg-green-700/20 border-green-500/50 text-green-500 hover:bg-green-500 hover:text-black'
                            : 'bg-red-900/40 border-red-500/40 text-red-500 hover:bg-red-500 hover:text-black'
                          }`}
                        >
                          {banType === 'IP' && 'إصدار أمر حظر الـ IP المستهدف'}
                          {banType === 'DEVICE' && 'إصدار أمر حظر بصمة المتصفح'}
                          {banType === 'UNBAN' && 'إلغاء الحظر وتفعيل الاتصال'}
                        </button>
                      </div>
                    </div>

                    {/* Custom Alert Message Announcement Hub (Public Broadcast Setup) */}
                    <div className="bg-black/80 border border-[#00ff00]/20 p-6 mb-8 relative z-10 backdrop-blur-md">
                      <h3 className="text-xs font-black text-[#00ff00] uppercase tracking-widest mb-6 flex items-center justify-between flex-row-reverse">
                         <div className="flex items-center gap-3">
                           <Wand2 className="w-4 h-4 text-[#00ff00]" /> نشر تنبيه/رسالة مخصصة على شاشة الموقع (Site-Wide Custom Alert)
                         </div>
                         <span className="text-[9px] text-[#00ff00]/40 font-mono">BROADCAST_HUB_V5.0</span>
                      </h3>
                      <div className="space-y-4">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div className="md:col-span-2 space-y-1">
                            <span className="text-[8px] text-[#00ff00]/40 uppercase font-black px-1 text-right block">نص التنبيه الذي سيظهر لجميع زوار الموقع</span>
                            <textarea 
                              rows={2}
                              value={adminAlertMessage}
                              onChange={(e) => setAdminAlertMessage(e.target.value)}
                              placeholder="أدخل الرسالة التحذيرية أو إعلان النظام العاجل للزوار هنا..."
                              className="w-full bg-black/60 border border-[#00ff00]/30 p-3 text-sm text-[#00ff00] outline-none focus:border-[#00ff00] text-right"
                            />
                          </div>
                          <div className="space-y-1">
                            <span className="text-[8px] text-[#00ff00]/40 uppercase font-black px-1 text-right block">مستوى خطورة اللوحة ولونها</span>
                            <select
                              value={adminAlertType}
                              onChange={(e) => setAdminAlertType(e.target.value as any)}
                              className="w-full h-[68px] bg-black/60 border border-[#00ff00]/30 p-3 text-sm text-[#00ff00] outline-none focus:border-[#00ff00] text-right"
                            >
                              <option value="RED">🚨 أحمر أمني غامض (Neon Cyan/Danger)</option>
                              <option value="YELLOW">⚠️ أصفر إنذاري (Warning Alert)</option>
                              <option value="GREEN">❇️ أخضر إعلامي مبسط (Cyber Information)</option>
                            </select>
                          </div>
                        </div>
                        
                        <div className="flex items-center justify-between border-t border-[#00ff00]/10 pt-4 flex-row-reverse">
                          <div className="flex items-center gap-3 flex-row-reverse">
                            <span className="text-xs text-[#00ff00]/80">حالة ظهور اللوحة للزوار</span>
                            <button
                              onClick={() => {
                                const nextVal = !adminAlertEnabled;
                                setAdminAlertEnabled(nextVal);
                                handleUpdateAnnouncement(adminAlertMessage, nextVal, adminAlertType);
                              }}
                              className={`px-4 py-2 text-[10px] uppercase font-bold tracking-widest transition-all border ${
                                adminAlertEnabled 
                                ? 'bg-red-500/10 border-red-500 text-red-400' 
                                : 'bg-[#00ff00]/10 border-[#00ff00]/40 text-[#00ff00]'
                              }`}
                            >
                              {adminAlertEnabled ? 'تعطيل رسالة الموقع (ACTIVE)' : 'تفعيل رسالة الموقع (DISABLED)'}
                            </button>
                          </div>
                          
                          <button 
                            onClick={() => handleUpdateAnnouncement(adminAlertMessage, adminAlertEnabled, adminAlertType)}
                            className="px-6 h-[40px] bg-[#00ff00]/20 border border-[#00ff00]/40 text-[#00ff00] hover:bg-[#00ff00] hover:text-black transition-all text-xs font-black uppercase tracking-widest"
                          >
                            تحديث وحفظ الإعلان العام للزوار
                          </button>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 relative z-10 flex-1 min-h-[500px]">
                      {/* Left Column: Interactive Danger/Attempt Logs Feed */}
                      <div className="bg-black/80 border border-[#00ff00]/20 flex flex-col backdrop-blur-md overflow-hidden h-[500px]">
                        <div className="bg-red-500/10 px-6 py-3 border-b border-red-500/20 flex items-center justify-between">
                          <span className="text-xs font-black uppercase tracking-widest text-red-500 flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-red-500 animate-pulse" /> رصد محاولات الاختراق والنسخ المباشرة ({historyLogs.length})
                          </span>
                          <span className="text-[9px] text-red-500/40 font-mono">LIVE_ATTEMPTS</span>
                        </div>
                        <div className="flex-1 overflow-auto custom-scrollbar p-2 space-y-3">
                          {historyLogs.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center opacity-20 gap-4">
                              <Cpu className="w-12 h-12 text-[#00ff00]" />
                              <p className="text-sm font-black uppercase tracking-widest text-[#00ff00]">No Hacking or Copy Attempts Logged</p>
                            </div>
                          ) : (
                            historyLogs.map((log: any) => {
                              // Translate event types to beautiful, simple Arabic for the admin
                              let arabicType = log.type || 'نشاط غير معروف';
                              if (log.type === 'DEVTOOLS_SUSPICION') arabicType = 'رصد فتح أدوات المطورين (DevTools)';
                              else if (log.type === 'RIGHT_CLICK_INTERCEPT') arabicType = 'محاولة استخدام الزر الأيمن (كليك يمين)';
                              else if (log.type === 'TAMPER_KEY_COMBO') arabicType = 'محاولة استخدام اختصارات الكود';
                              else if (log.type === 'COPY_ATTEMPT') arabicType = 'محاولة نسخ نصوص الموقع ❌';
                              else if (log.type === 'F12_KEY_BLOCK') arabicType = 'محاولة استخدام مفتاح F12 للـ Inspect';
                              else if (log.type === 'DEVTOOLS_SHORTCUT_BLOCK') arabicType = 'استخدام اختصار Inspect المتقدم';
                              else if (log.type === 'SAVE_PRINT_PREVENTION') arabicType = 'محاولة حفظ/طباعة الصفحة';
                              else if (log.type === 'COPY_SHORTCUT_BLOCK') arabicType = 'محاولة النسخ باختصارات الكيبورد';
                              else if (log.type === 'PERFORMANCE_ANOMALY') arabicType = 'فحص أداء الصفحة المتقدم (تحليل وسرقة)';
                              else if (log.type === 'UNAUTHORIZED_DEPLOYMENT') arabicType = 'محاولة تشغيل نسخة مسروقة';

                              return (
                                <div key={log.id} className="p-3 border border-red-500/15 hover:border-red-500/40 bg-red-950/5 transition-all text-right space-y-2 rounded-sm">
                                  <div className="flex items-center justify-between border-b border-red-500/10 pb-1.5 flex-row-reverse">
                                    <span className="text-xs font-bold text-red-400">{arabicType}</span>
                                    <span className="text-[10px] font-mono text-[#00ff00]/60">
                                      {log.timestamp?.seconds 
                                        ? new Date(log.timestamp.seconds * 1000).toLocaleTimeString() 
                                        : new Date().toLocaleTimeString()}
                                    </span>
                                  </div>
                                  <div className="flex flex-col gap-1 text-[11px] text-[#00ff00]/80 font-mono">
                                    <div className="flex justify-between items-center flex-row-reverse">
                                      <span className="text-red-400 font-bold">العنوان IP:</span>
                                      <div className="flex items-center gap-2">
                                        <button
                                          onClick={() => copyToClipboard(log.ip, `log_${log.id}`)}
                                          className="px-1.5 py-0.5 border border-red-500/20 hover:border-red-500/60 bg-red-500/5 text-red-400 transition-colors rounded-[2px] text-[8px] font-mono cursor-pointer"
                                          title="نسخ IP"
                                        >
                                          {copiedText[`log_${log.id}`] ? '✅ تم النسخ' : 'نسخ IP'}
                                        </button>
                                        <span className="text-red-300 font-bold bg-red-950/30 px-1">{log.ip}</span>
                                      </div>
                                    </div>
                                    <div className="flex justify-between items-center flex-row-reverse">
                                      <span className="text-red-400">الموقع الجغرافي:</span>
                                      <span className="text-[#00ff00]/60">{log.location || 'غير معروف'}</span>
                                    </div>
                                    {log.details && (
                                      <div className="mt-1 bg-black/60 p-2 border border-red-500/5 text-[10px] text-red-300/80 leading-relaxed text-right break-words self-end w-full" dir="ltr">
                                        {log.details}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              );
                            })
                          )}
                        </div>
                      </div>

                      {/* Right Column: Banned Users & IPs List */}
                      <div className="bg-black/80 border border-[#00ff00]/20 flex flex-col backdrop-blur-md overflow-hidden h-[500px]">
                        <div className="bg-[#00ff00]/10 px-6 py-3 border-b border-[#00ff00]/20 flex items-center justify-between">
                          <span className="text-xs font-black uppercase tracking-widest text-[#00ff00]">قائمة المحظورين والعمليات المباشرة ({globalBans.length})</span>
                          <div className="flex gap-1">
                            <div className="w-1.5 h-1.5 rounded-full bg-[#00ff00] animate-pulse" />
                            <div className="w-1.5 h-1.5 rounded-full bg-[#00ff00]/30" />
                            <div className="w-1.5 h-1.5 rounded-full bg-[#00ff00]/30" />
                          </div>
                        </div>
                        <div className="flex-1 overflow-auto custom-scrollbar">
                          {globalBans.length === 0 ? (
                            <div className="h-full flex flex-col items-center justify-center opacity-20 gap-4">
                              <Cpu className="w-12 h-12" />
                              <p className="text-sm font-black uppercase tracking-widest">No Active Threat Bans Registered</p>
                            </div>
                          ) : (
                            <table className="w-full text-right" dir="rtl">
                              <thead className="bg-[#050505] sticky top-0 z-10 border-b border-[#00ff00]/10">
                                <tr className="text-[9px] text-[#00ff00]/40 uppercase font-bold text-right">
                                  <th className="p-4 text-right">المستهدف IP / البصمة</th>
                                  <th className="p-4 text-right">نوع الحظر</th>
                                  <th className="p-4 text-right">السبب</th>
                                  <th className="p-4 text-right">التاريخ</th>
                                  <th className="p-4 text-left">التحكم</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-[#00ff00]/5">
                                {globalBans.map((ban: any) => (
                                    <tr key={ban.id} className="hover:bg-[#00ff00]/5 transition-colors group text-right">
                                      <td className="p-4 text-sm font-mono text-[#00ff00] font-bold text-right flex items-center justify-end gap-2">
                                        <button
                                          onClick={() => copyToClipboard(ban.ip, `ban_${ban.id}`)}
                                          className="p-1 border border-[#00ff00]/10 hover:border-[#00ff00]/40 bg-[#00ff00]/5 hover:bg-[#00ff00]/10 text-[#00ff00] transition-colors rounded-[2px]"
                                          title="نسخ"
                                        >
                                          {copiedText[`ban_${ban.id}`] ? (
                                            <span className="text-[8px] text-green-400">تم النسخ</span>
                                          ) : (
                                            <Copy className="w-3 h-3" />
                                          )}
                                        </button>
                                        <span>{ban.ip}</span>
                                      </td>
                                    <td className="p-4 text-xs font-bold text-right">
                                      {ban.type === 'DEVICE' ? (
                                        <span className="text-yellow-500 bg-yellow-950/20 px-1 border border-yellow-500/20 rounded-[2px]">📱 مستخدم (جهاز)</span>
                                      ) : (
                                        <span className="text-red-500 bg-red-950/20 px-1 border border-red-500/20 rounded-[2px]">🌐 عنوان IP</span>
                                      )}
                                    </td>
                                    <td className="p-4 text-xs font-bold text-red-500 uppercase text-right">{ban.reason}</td>
                                    <td className="p-4 text-[10px] font-mono text-[#00ff00]/40 text-right">
                                      {new Date(ban.timestamp?.seconds * 1000 || Date.now()).toLocaleTimeString()}
                                    </td>
                                    <td className="p-4 text-left">
                                      <button 
                                        onClick={() => handleUnban(ban.id)}
                                        className="px-4 py-1.5 border border-red-500/30 text-[9px] font-black text-red-500 bg-red-500/10 hover:bg-red-500 hover:text-black transition-all uppercase tracking-widest"
                                      >
                                        فك الحظر
                                      </button>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'SOURCE' && (
              <motion.div
                key="source-tab"
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 10 }}
                className="space-y-6"
              >
                {/* Input Panel */}
          <section className="bg-black/60 border border-[#00ff00]/20 shadow-2xl relative">
            <div className="px-4 py-2 border-b border-[#00ff00]/20 bg-[#00ff00]/5 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-[#00ff00]" />
                <span className="text-[10px] font-mono font-bold tracking-widest text-[#00ff00]/80 lowercase">input.io // script_buffer</span>
              </div>
              <div className="flex items-center gap-4">
                <label className="cursor-pointer flex items-center gap-1.5 px-2 py-1 border border-[#00ff00]/20 hover:bg-[#00ff00]/10 transition-all text-[#00ff00]/70 hover:text-[#00ff00]">
                  <Upload className="w-3 h-3" />
                  <span className="text-[9px] font-bold uppercase tracking-tighter">رفع ملف</span>
                  <input type="file" className="hidden" onChange={handleFileUpload} accept=".lua,.txt" />
                </label>
                <button onClick={reset} className="flex items-center gap-1.5 px-2 py-1 border border-[#003300]/20 hover:bg-[#003300]/10 transition-all text-[#00ff00]/50 hover:text-[#00ff00]">
                  <Trash2 className="w-3 h-3" />
                  <span className="text-[9px] font-bold uppercase tracking-tighter">مسح</span>
                </button>
              </div>
            </div>
            <textarea
              ref={textRef}
              defaultValue={input}
              className="w-full h-80 bg-transparent p-4 outline-none resize-none code-area text-base select-text custom-scrollbar"
              placeholder="-- ضع الكود البرمجي هنا (يدعم الأكواد الطويلة جداً)..."
              spellCheck="false"
              dir="ltr"
            />
            <div className="px-4 py-2 bg-[#00ff00]/5 flex items-center justify-end border-t border-[#00ff00]/10">
              <button
                onClick={handleDeobfuscate}
                disabled={isLoading}
                className="bg-[#00ff00] hover:bg-[#00ff00]/80 disabled:opacity-50 text-black px-6 py-2 font-black uppercase tracking-widest shadow-[0_0_15px_#00ff00] transition-all hover:scale-105 active:scale-95 flex items-center gap-2"
              >
                {isLoading ? <Activity className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
                بدء التنظيف المبدئي
              </button>
            </div>
          </section>

          {/* Result Panel */}
          <AnimatePresence>
            {output && (
              <motion.section
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-black/60 border border-[#00ff00]/20 shadow-2xl"
              >
                <div className="px-4 pt-4 pb-2">
                  <div className="flex items-center gap-2 overflow-x-auto pb-2 custom-scrollbar no-scrollbar">
                    {selectedObfs.map((obf, i) => (
                      <div key={obf} className="flex items-center gap-2 shrink-0">
                        <div className="flex flex-col items-center">
                           <Layers className={`w-3 h-3 ${i === selectedObfs.length - 1 ? 'text-[#00ff00]' : 'text-white/20'}`} />
                           <div className="h-4 w-px bg-white/10" />
                        </div>
                        <div className={`px-2 py-1 border text-[8px] font-bold uppercase tracking-widest ${
                          i === selectedObfs.length - 1 ? 'border-[#00ff00] text-[#00ff00] bg-[#00ff00]/10' : 'border-white/10 text-white/30'
                        }`}>
                          {obf}
                        </div>
                        {i < selectedObfs.length - 1 && <ChevronRight className="w-3 h-3 text-white/10" />}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="px-4 py-2 border-b border-[#00ff00]/20 bg-[#00ff00]/10 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Zap className="w-4 h-4 text-[#00ff00]" />
                    <span className="text-[10px] font-mono font-bold text-[#00ff00]/80 uppercase">decompiled_source.lua</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <button 
                      onClick={() => copyToClipboard(output.content)}
                      className="text-[#00ff00] hover:bg-[#00ff00]/10 px-2 py-1 text-[9px] font-bold border border-[#00ff00]/30 transition-colors uppercase tracking-widest flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> نسخ الكود
                    </button>
                    <button 
                      onClick={handleNormalize}
                      disabled={isNormalizing || isAiLoading}
                      className="text-[#00ff00] hover:bg-[#00ff00]/10 px-2 py-1 text-[9px] font-bold border border-[#00ff00]/30 transition-colors uppercase tracking-widest flex items-center gap-1"
                    >
                      <Wand2 className="w-3 h-3" /> تجميل الأسماء
                    </button>
                    <button 
                      onClick={handleScanVulnerabilities}
                      disabled={isScanningVulnerabilities || isAiLoading}
                      className="text-[#00ff00] hover:bg-[#00ff00]/10 px-2 py-1 text-[9px] font-bold border border-[#00ff00]/30 transition-colors uppercase tracking-widest flex items-center gap-1"
                    >
                      <ShieldAlert className="w-3 h-3" /> فحص الثغرات
                    </button>
                    <button 
                      onClick={() => downloadFile(output.content, `extracted_${selectedObfs.join('_').toLowerCase()}.lua`)}
                      className="text-[#00ff00] hover:bg-[#00ff00]/10 px-2 py-1 text-[9px] font-bold border border-[#00ff00]/30 transition-colors uppercase tracking-widest flex items-center gap-1"
                    >
                      <Download className="w-3 h-3" /> تحميل الكود
                    </button>
                  </div>
                </div>
                
                {/* Search Bar Panel */}
                <div className="px-4 py-3 bg-black/40 border-b border-[#00ff00]/20 flex flex-col sm:flex-row-reverse sm:items-center justify-between gap-3 text-right">
                  <div className="flex items-center gap-2 justify-end">
                    <Search className="w-3.5 h-3.5 text-[#00ff00]/70" />
                    <span className="text-[10px] font-mono font-bold text-[#00ff00]/80 uppercase">البحث الذكي في الكود // code_query</span>
                  </div>
                  
                  <div className="flex items-center gap-3 justify-end w-full sm:w-auto flex-row-reverse sm:flex-row">
                    {searchQuery && (
                      <div className="text-[10px] font-mono text-[#00ff00]/80 flex items-center gap-1 bg-[#00ff00]/10 px-2 py-1 border border-[#00ff00]/20 rounded-[2px]">
                        <span>تطابق: {matchingLineNumbers.length > 0 ? currentMatchIndex + 1 : 0} / {matchingLineNumbers.length}</span>
                      </div>
                    )}
                    
                    <div className="relative flex-1 sm:w-64 max-w-xs">
                      <input
                        type="text"
                        placeholder="ابحث عن دوال، متغيرات أو أكواد..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handleNextMatch();
                          }
                        }}
                        className="w-full bg-black/80 border border-[#00ff00]/30 text-[#00ff00] pl-6 pr-3 py-1 text-xs placeholder-[#00ff00]/30 outline-none focus:border-[#00ff00]/80 rounded-[2px]"
                        dir="rtl"
                      />
                      {searchQuery && (
                        <button
                          onClick={() => setSearchQuery('')}
                          className="absolute left-2 top-1/2 -translate-y-1/2 text-[10px] font-bold text-[#00ff00]/50 hover:text-[#00ff00] cursor-pointer"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                    
                    <div className="flex items-center border border-[#00ff00]/30 bg-black/40 rounded-[2px]">
                      <button
                        onClick={handlePrevMatch}
                        disabled={matchingLineNumbers.length === 0}
                        className="p-1 px-2.5 text-[#00ff00] hover:bg-[#00ff00]/10 disabled:opacity-30 border-r border-[#00ff00]/20 text-xs font-mono font-bold"
                        title="البحث عن المطابقة السابقة"
                      >
                        السابق
                      </button>
                      <button
                        onClick={handleNextMatch}
                        disabled={matchingLineNumbers.length === 0}
                        className="p-1 px-2.5 text-[#00ff00] hover:bg-[#00ff00]/10 disabled:opacity-30 text-xs font-mono font-bold"
                        title="البحث عن المطابقة التالية"
                      >
                        التالي
                      </button>
                    </div>
                  </div>
                </div>
                
                <div className="p-4 relative">
                  <div className={`w-full max-h-[600px] overflow-auto bg-[#001000]/40 rounded shadow-inner custom-scrollbar transition-all duration-500`}>
                    {!isScrambling && status === 'PROCESS_COMPLETE' ? (
                      <SyntaxHighlighter 
                        language="lua" 
                        style={atomDark}
                        customStyle={{ background: 'transparent', padding: '1rem', fontSize: '0.8rem', fontFamily: 'JetBrains Mono, monospace' }}
                        wrapLines={true}
                        lineProps={(lineNumber) => {
                          const isMatch = searchQuery && matchingLineNumbers.includes(lineNumber);
                          const isCurrentMatch = searchQuery && matchingLineNumbers[currentMatchIndex] === lineNumber;
                          
                          const props: any = {
                            id: `code-line-${lineNumber}`,
                          };
                          
                          if (isCurrentMatch) {
                            props.style = { 
                              display: 'block', 
                              backgroundColor: 'rgba(0, 255, 0, 0.35)', 
                              borderRight: '3px solid #00ff00', 
                              paddingRight: '4px' 
                            };
                          } else if (isMatch) {
                            props.style = { 
                              display: 'block', 
                              backgroundColor: 'rgba(0, 255, 0, 0.12)',
                              borderRight: '1px solid rgba(0, 255, 0, 0.3)'
                            };
                          }
                          return props;
                        }}
                      >
                        {displayedContent}
                      </SyntaxHighlighter>
                    ) : (
                      <pre className={`p-4 text-[0.8rem] font-mono leading-relaxed transition-all duration-300 ${isScrambling ? 'text-[#00ff00]/40' : 'text-blue-300'}`}>
                        {displayedContent}
                      </pre>
                    )}
                  </div>
                </div>

                <div className="px-4 py-4 bg-[#00ff00]/5 border-t border-[#00ff00]/20 flex flex-col md:flex-row items-center justify-between gap-4">
                  <div className="flex items-center gap-3 text-[#00ff00]/80">
                    <BrainCircuit className="w-6 h-6 opacity-60" />
                    <div>
                      <p className="font-bold text-xs tracking-wide">الاسترجاع الشامل (Full AI Recovery)</p>
                      <p className="text-[8px] opacity-60 uppercase">Single-Click Neural Reconstruction</p>
                    </div>
                  </div>
                  <div className="w-full md:w-auto">
                    <button
                      onClick={handleAiAnalyze}
                      disabled={isAiLoading || isNormalizing || isScanningVulnerabilities || !output.success}
                      className="w-full md:min-w-[240px] bg-green-500 hover:bg-green-400 text-black px-8 py-3 font-black uppercase tracking-tighter shadow-[0_0_30px_rgba(0,255,0,0.5)] transition-all flex items-center justify-center gap-3 text-sm group"
                    >
                      {isAiLoading ? <Activity className="w-4 h-4 animate-pulse" /> : <Search className="w-4 h-4 group-hover:scale-125 transition-transform" />}
                      استعادة وفك التشفير كاملاً
                    </button>
                  </div>
                </div>
              </motion.section>
            )}
          </AnimatePresence>
        </motion.div>
      )}

      {activeTab === 'ANALYSIS' && (
        <motion.div
           key="analysis-tab"
           initial={{ opacity: 0, x: -10 }}
           animate={{ opacity: 1, x: 0 }}
           exit={{ opacity: 0, x: 10 }}
           className="space-y-6"
        >
          {/* AI Analysis View */}
          <AnimatePresence mode="wait">
            {aiAnalysis ? (
              <motion.section
                key="analysis-view"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.4, ease: [0.4, 0, 0.2, 1] }}
                className="bg-[#050505] border border-green-500/30 p-1 relative overflow-hidden shadow-[0_0_40px_rgba(0,255,0,0.05)]"
              >
                {isAiLoading && <div className="analyser-line" />}
                <div className="px-4 py-2 border-b border-green-500/30 bg-green-500/10 flex flex-wrap gap-2 items-center justify-between relative z-20">
                  <div className="flex items-center gap-2">
                    <Activity className={`w-4 h-4 ${isAiLoading ? 'animate-pulse text-yellow-400' : 'text-green-400'}`} />
                    <h2 className="text-[10px] font-black text-green-100 uppercase tracking-widest terminal-title">
                      {isAiLoading ? 'SYSTEM_RECONSTRUCTING_LOGIC...' : 'DEOBFUSCATED_SOURCE_CODE // الكود المفكك كاملاً'}
                    </h2>
                  </div>
                  {!isAiLoading && (
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={copyAiDeobfuscatedCode}
                        className="text-green-400 text-[9px] border border-green-500/40 px-2.5 py-1 bg-green-500/5 hover:bg-green-500 hover:text-black transition-all uppercase font-bold rounded-[2px] flex items-center gap-1 cursor-pointer"
                      >
                        {copiedText['copy_ai_decoded'] ? '✅ تم نسخ الكود' : '📋 نسخ الكود الكامل'}
                      </button>
                      <button 
                        onClick={downloadAiDeobfuscatedCode}
                        className="text-green-500 text-[9px] border border-green-500/50 px-2.5 py-1 hover:bg-green-500 hover:text-black transition-all uppercase font-bold rounded-[2px] cursor-pointer"
                      >
                        💾 تحميل الكود المفكك
                      </button>
                    </div>
                  )}
                </div>
                
                {isAiLoading && (
                  <div className="loading-bar-container">
                    <div className="loading-bar-fill" />
                  </div>
                )}

                <div className="p-6 text-green-300 leading-relaxed font-mono text-sm max-w-none bg-black/80 max-h-[5000px] overflow-auto custom-ai-output relative z-10 scroll-smooth">
                  <div className="code-stream-enter">
                    <Markdown>{aiAnalysis}</Markdown>
                  </div>
                </div>
              </motion.section>
            ) : isAiLoading ? (
              <motion.section
                key="loading-view"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="bg-black/60 border border-[#00ff00]/20 p-12 flex flex-col items-center justify-center gap-4 min-h-[300px]"
              >
                <div className="relative">
                  <div className="w-16 h-16 border-2 border-green-500/20 rounded-full animate-ping" />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <BrainCircuit className="w-8 h-8 text-green-500 animate-pulse" />
                  </div>
                </div>
                <div className="text-center space-y-2">
                  <p className="text-[#00ff00] font-bold terminal-title uppercase tracking-widest">تحميل المنطق البرمجي...</p>
                  <div className="w-48 mx-auto">
                    <div className="loading-bar-container">
                      <div className="loading-bar-fill" />
                    </div>
                  </div>
                  <p className="text-[8px] text-[#00ff00]/40 uppercase animate-pulse">Scanning Bytecode & Reconstructing Functions</p>
                </div>
              </motion.section>
            ) : null}
          </AnimatePresence>
        </motion.div>
      )}
        {activeTab === 'LOGS' && (
          <motion.div
            key="logs-tab"
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 10 }}
            className="bg-black/60 border border-[#00ff00]/20 p-8 min-h-[400px] font-mono whitespace-pre-wrap text-sm text-[#00ff00]/80"
          >
            <div className="flex items-center gap-4 mb-6 pb-4 border-b border-[#00ff00]/20">
              <Terminal className="w-6 h-6 animate-pulse" />
              <h2 className="text-xl font-black uppercase tracking-tighter">Full_System_Diagnostics</h2>
            </div>
            <div className="space-y-2">
              <div className="text-[10px] opacity-40 uppercase mb-4">Start_Sequence_Initiated...</div>
              {systemLogs.map((log, i) => (
                <div key={i} className={`flex items-start gap-4 ${
                  log.type === 'success' ? 'text-green-500' : log.type === 'warn' ? 'text-yellow-500' : 'text-white/40'
                }`}>
                  <span className="opacity-20">[{new Date().toLocaleTimeString()}]</span>
                  <span>{log.msg}</span>
                </div>
              ))}
              <motion.div 
                animate={{ opacity: [0, 1] }} 
                transition={{ repeat: Infinity, duration: 0.8 }}
                className="w-2 h-4 bg-[#00ff00] inline-block ml-1"
              />
            </div>
          </motion.div>
        )}
        </AnimatePresence>
      </div>
    </main>

      {/* Retro HUD Decoration */}
      <div className="fixed bottom-10 right-10 flex gap-1 items-end z-40 opacity-30">
        {[40, 60, 30, 80, 50, 90, 20].map((h, i) => (
          <div key={i} className="w-1 bg-[#00ff00]" style={{ height: `${h}px` }} />
        ))}
      </div>

      <footer className="fixed bottom-0 left-0 right-0 py-2 bg-black border-t border-[#00ff00]/10 z-50 px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
        <a 
          href="https://discord.com/invite/uuuu" 
          target="_blank" 
          rel="noopener noreferrer"
          className="text-[9px] text-[#00ff00]/40 tracking-[0.2em] font-mono uppercase hover:text-[#00ff00] transition-colors"
        >
          Alzaabi Team // جميع الحقوق محفوظة © {new Date().getFullYear()}
        </a>
        <div className="flex items-center gap-4">
          <a 
            href="https://discord.com/invite/uuuu" 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-[9px] text-[#00ff00]/60 hover:text-[#00ff00] transition-colors font-mono tracking-widest border border-[#00ff00]/20 px-2 py-0.5 hover:bg-[#00ff00]/10 flex items-center gap-2"
          >
            ALZAABI TEAM
          </a>
          <p className="hidden sm:block text-[9px] text-[#00ff00]/20 tracking-[0.5em] font-mono">
            UID: {uid}
          </p>
        </div>
      </footer>
    </div>
  );
}
