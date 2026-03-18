import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import TerminalLogs from '../components/TerminalLogs';
import { Activity, Crown, Radar, ShieldCheck, Target, Trash2, Zap } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { isAdminRole, isPremiumRole, roleBadge } from '../utils/roles.js';
import { API_URL, buildWebSocketUrl } from '../config/api.js';

const SCAN_OPTIONS = [
  {
    value: 'Basic Scan',
    label: 'Basic Scan',
    description: 'subfinder + httpx',
    premiumOnly: false,
  },
  {
    value: 'Recon Scan',
    label: 'Recon Scan',
    description: 'crawling, JS intelligence, GraphQL discovery',
    premiumOnly: true,
  },
  {
    value: 'Full Scan',
    label: 'Full Scan',
    description: 'recon + ffuf + nuclei',
    premiumOnly: true,
  },
];

export default function NewScan() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [target, setTarget] = useState(location.state?.target || '');
  const [scanType, setScanType] = useState('Recon Scan');
  const [isLoading, setIsLoading] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [monitorDomains, setMonitorDomains] = useState('');
  const [monitorInterval, setMonitorInterval] = useState(720);
  const [automationTargets, setAutomationTargets] = useState([]);
  const [automationLoading, setAutomationLoading] = useState(false);
  const wsRef = useRef(null);
  const scanStatusPollRef = useRef(null);
  const scanStatusPollingActiveRef = useRef(false);
  const backendLogCountRef = useRef(0);
  const loadingRef = useRef(false);

  const premiumAccess = isPremiumRole(user?.role);
  const adminAccess = isAdminRole(user?.role);

  const featureList = useMemo(() => {
    if (adminAccess) {
      return ['Full recon pipeline', 'JS secret discovery', 'GraphQL probing', 'ffuf + nuclei', 'continuous monitoring', 'admin controls'];
    }
    if (premiumAccess) {
      return ['Full recon pipeline', 'JS secret discovery', 'GraphQL probing', 'ffuf + nuclei', 'continuous monitoring'];
    }
    return ['Basic scan only', 'subfinder', 'httpx', 'live telemetry'];
  }, [adminAccess, premiumAccess]);

  useEffect(() => {
    loadingRef.current = isLoading;
  }, [isLoading]);

  useEffect(() => {
    if (!premiumAccess) {
      setScanType('Basic Scan');
      setAutomationTargets([]);
      return;
    }
    fetchAutomationTargets();
  }, [premiumAccess]);

  useEffect(() => {
    return () => {
      stopScanStatusPolling();
      if (wsRef.current) {
        wsRef.current.onopen = null;
        wsRef.current.onmessage = null;
        wsRef.current.onerror = null;
        wsRef.current.onclose = null;
        wsRef.current.close();
      }
    };
  }, []);

  const appendLog = (message) => setLogs((prev) => [...prev, message]);

  const appendBackendLog = (message) => {
    backendLogCountRef.current += 1;
    appendLog(message);
  };

  const stopScanStatusPolling = () => {
    if (scanStatusPollRef.current) {
      clearInterval(scanStatusPollRef.current);
      scanStatusPollRef.current = null;
    }
    scanStatusPollingActiveRef.current = false;
  };

  const startScanStatusPolling = (scanId, fallbackMessage) => {
    if (scanStatusPollingActiveRef.current) return;
    scanStatusPollingActiveRef.current = true;

    if (fallbackMessage) {
      appendLog(fallbackMessage);
    }

    const pollStatus = async () => {
      try {
        const [scanRes, logsRes] = await Promise.all([
          axios.get(`${API_URL}/scans/${scanId}`),
          axios.get(`${API_URL}/scans/${scanId}/logs`),
        ]);

        const history = logsRes.data?.logs || [];
        const unseenLogs = history.slice(backendLogCountRef.current);
        unseenLogs.forEach((line) => appendBackendLog(line));

        const status = scanRes.data?.status;
        if (status === 'Completed') {
          appendLog('[SYSTEM] Scan completed. Open full report for details.');
          setIsLoading(false);
          stopScanStatusPolling();
        } else if (status === 'Failed') {
          const errorMsg = scanRes.data?.summary?.error;
          appendLog(errorMsg
            ? `[ERROR] Scan failed: ${errorMsg}`
            : '[SYSTEM] Scan failed. Open full report for details.');
          setIsLoading(false);
          stopScanStatusPolling();
        }
      } catch (err) {
        console.error(err);
      }
    };

    pollStatus();
    scanStatusPollRef.current = setInterval(pollStatus, 3000);
  };

  const fetchAutomationTargets = async () => {
    try {
      const res = await axios.get(`${API_URL}/scans/automation/targets`);
      setAutomationTargets(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target) return;
    if (!premiumAccess && scanType !== 'Basic Scan') {
      appendLog('[ERROR] Free users can only launch Basic Scan operations.');
      return;
    }

    stopScanStatusPolling();
    backendLogCountRef.current = 0;
    setIsLoading(true);
    setLogs([]);
    try {
      const res = await axios.post(`${API_URL}/scans/`, {
        target_domain: target,
        scan_type: scanType
      });
      
      const scanId = res.data.id;
      setActiveScanId(scanId);
      connectWebSocket(scanId);
    } catch (err) {
      console.error(err);
      appendLog(`[ERROR] Failed to initialize scan: ${err.response?.data?.detail || err.message}`);
      stopScanStatusPolling();
      setIsLoading(false);
    }
  };

  const connectWebSocket = (scanId) => {
    if (wsRef.current) {
      wsRef.current.onopen = null;
      wsRef.current.onmessage = null;
      wsRef.current.onerror = null;
      wsRef.current.onclose = null;
      wsRef.current.close();
    }

    const socket = new WebSocket(buildWebSocketUrl(`/ws/scan/${scanId}`));
    let socketComplete = false;
    let fallbackActivated = false;

    const activateFallback = (message) => {
      if (fallbackActivated) return;
      fallbackActivated = true;
      startScanStatusPolling(scanId, message);
    };
    
    socket.onopen = () => appendLog('[SYSTEM] Secure neural link established. Waiting for scanner engine...');
    
    socket.onmessage = (event) => {
      appendBackendLog(event.data);
      if (event.data.includes('Results saved to database') || event.data.includes('Scan failed')) {
        socketComplete = true;
        stopScanStatusPolling();
        setIsLoading(false);
      }
    };
    
    socket.onerror = () => {
      if (wsRef.current !== socket) return;
      activateFallback('[SYSTEM] Live telemetry switched to polling mode.');
    };

    socket.onclose = () => {
      if (wsRef.current !== socket) return;
      if (loadingRef.current && !socketComplete) {
        activateFallback('[SYSTEM] Live telemetry disconnected. Polling mode active.');
      } else {
        stopScanStatusPolling();
      }
    };

    wsRef.current = socket;
  };

  const handleCreateMonitoring = async (e) => {
    e.preventDefault();
    const domains = monitorDomains
      .split(/[\n,]+/)
      .map((domain) => domain.trim())
      .filter(Boolean);

    if (!domains.length) return;

    setAutomationLoading(true);
    try {
      await axios.post(`${API_URL}/scans/automation/targets`, {
        domains,
        scan_type: 'Recon Scan',
        interval_minutes: Number(monitorInterval),
      });
      appendLog(`[SYSTEM] Monitoring targets armed for ${domains.length} domain(s).`);
      setMonitorDomains('');
      await fetchAutomationTargets();
    } catch (err) {
      console.error(err);
      appendLog(`[ERROR] Monitoring setup failed: ${err.response?.data?.detail || err.message}`);
    } finally {
      setAutomationLoading(false);
    }
  };

  const handleToggleMonitoring = async (targetId, enabled) => {
    try {
      await axios.patch(`${API_URL}/scans/automation/targets/${targetId}`, { enabled });
      await fetchAutomationTargets();
    } catch (err) {
      console.error(err);
    }
  };

  const handleDeleteMonitoring = async (targetId) => {
    try {
      await axios.delete(`${API_URL}/scans/automation/targets/${targetId}`);
      await fetchAutomationTargets();
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white uppercase tracking-widest font-mono flex items-center gap-3">
          <Target className="text-cyber-blue" />
          Initialize Operation
        </h1>
        <p className="text-cyber-dim mt-2 font-mono text-sm max-w-2xl">
          Deploy AI reconnaissance engine against target domain. Unauthorized probing is strictly prohibited.
          <br/><span className="text-cyber-pink font-bold mt-2 inline-block">WARNING: Only scan domains you own or have explicit permission to test.</span>
        </p>
        <div className="mt-4 glass-panel rounded-lg p-4 border border-cyber-blue/20 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="text-xs uppercase tracking-[0.3em] text-cyber-dim font-mono">Access tier</div>
            <div className="text-cyber-blue font-mono text-lg mt-1">{roleBadge(user?.role)}</div>
          </div>
          <div className="flex flex-wrap gap-2">
            {featureList.map((feature) => (
              <span key={feature} className="px-3 py-1 rounded-full text-xs font-mono border border-cyber-blue/30 text-cyber-blue bg-cyber-blue/10">
                {feature}
              </span>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-1">
          <form onSubmit={handleSubmit} className="glass-panel p-6 rounded-lg space-y-6">
            <div>
              <label className="block text-cyber-blue font-mono text-sm uppercase mb-2">Target Domain</label>
              <input 
                type="text" 
                required
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com"
                className="w-full bg-cyber-bg/50 border border-cyber-blue/30 text-white px-4 py-3 rounded outline-none focus:border-cyber-blue transition-colors font-mono"
                disabled={isLoading}
              />
            </div>

            <div>
              <label className="block text-cyber-purple font-mono text-sm uppercase mb-2">Operation Type</label>
              <select 
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                className="w-full bg-cyber-bg/50 border border-cyber-purple/30 text-white px-4 py-3 rounded outline-none focus:border-cyber-purple transition-colors font-mono appearance-none"
                disabled={isLoading}
              >
                {SCAN_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value} disabled={option.premiumOnly && !premiumAccess}>
                    {option.label} ({option.description})
                  </option>
                ))}
              </select>
              {!premiumAccess && (
                <p className="text-xs text-cyber-dim font-mono mt-2">
                  Upgrade to Premium to unlock Recon Scan, Full Scan, JavaScript intelligence, GraphQL discovery, ffuf, nuclei, and continuous monitoring.
                </p>
              )}
            </div>

            <button 
              type="submit" 
              disabled={isLoading || !target}
              className={`w-full py-3 flex items-center justify-center gap-2 font-bold uppercase tracking-widest transition-all duration-300 rounded ${isLoading ? 'bg-cyber-dim/20 text-cyber-dim border border-cyber-dim cursor-not-allowed' : 'bg-cyber-blue/20 border border-cyber-blue text-cyber-blue hover:bg-cyber-blue hover:text-cyber-bg glow-blue'}`}
            >
              <Zap className="w-5 h-5" /> 
              {isLoading ? 'Scanning...' : 'Execute'}
            </button>
          </form>

          <div className="glass-panel p-5 rounded-lg mt-4 border border-cyber-green/20">
            <div className="flex items-center gap-2 mb-3 text-cyber-green font-mono uppercase tracking-wider text-sm">
              <ShieldCheck className="w-4 h-4" /> Operation matrix
            </div>
            <div className="space-y-3 text-sm font-mono">
              <div className="flex items-start gap-3">
                <Activity className="w-4 h-4 mt-0.5 text-cyber-blue" />
                <div>
                  <div className="text-white">Basic</div>
                  <div className="text-cyber-dim">subfinder + httpx + live telemetry</div>
                </div>
              </div>
              <div className={`flex items-start gap-3 ${premiumAccess ? '' : 'opacity-50'}`}>
                <Radar className="w-4 h-4 mt-0.5 text-cyber-purple" />
                <div>
                  <div className="text-white">Recon</div>
                  <div className="text-cyber-dim">katana, gau, LinkFinder-style extraction, JavaScript endpoint discovery, GraphQL probing</div>
                </div>
              </div>
              <div className={`flex items-start gap-3 ${premiumAccess ? '' : 'opacity-50'}`}>
                <Crown className="w-4 h-4 mt-0.5 text-cyber-pink" />
                <div>
                  <div className="text-white">Full</div>
                  <div className="text-cyber-dim">directory fuzzing, nuclei findings, secrets reporting, downloadable recon report</div>
                </div>
              </div>
            </div>
          </div>

          {premiumAccess && (
            <div className="glass-panel p-6 rounded-lg mt-4 space-y-5 border border-cyber-purple/20">
              <div>
                <h3 className="text-cyber-purple font-mono uppercase tracking-wider flex items-center gap-2">
                  <Radar className="w-4 h-4" /> Bug bounty automation engine
                </h3>
                <p className="text-cyber-dim font-mono text-xs mt-2">
                  Queue recurring recon jobs for multiple domains. Fresh surface changes get tracked automatically.
                </p>
              </div>

              <form onSubmit={handleCreateMonitoring} className="space-y-4">
                <textarea
                  value={monitorDomains}
                  onChange={(e) => setMonitorDomains(e.target.value)}
                  rows={4}
                  placeholder={'example.com\napi.example.com'}
                  className="w-full bg-cyber-bg/50 border border-cyber-purple/30 text-white px-4 py-3 rounded outline-none focus:border-cyber-purple transition-colors font-mono text-sm"
                />
                <div>
                  <label className="block text-cyber-dim text-xs uppercase tracking-[0.3em] font-mono mb-2">Interval</label>
                  <select
                    value={monitorInterval}
                    onChange={(e) => setMonitorInterval(e.target.value)}
                    className="w-full bg-cyber-bg/50 border border-cyber-purple/30 text-white px-4 py-3 rounded outline-none focus:border-cyber-purple transition-colors font-mono appearance-none"
                  >
                    <option value={60}>Every hour</option>
                    <option value={360}>Every 6 hours</option>
                    <option value={720}>Every 12 hours</option>
                    <option value={1440}>Daily</option>
                  </select>
                </div>
                <button
                  type="submit"
                  disabled={automationLoading}
                  className="w-full py-3 bg-cyber-purple/20 border border-cyber-purple text-cyber-purple hover:bg-cyber-purple hover:text-cyber-bg font-bold uppercase tracking-widest transition-all duration-300 rounded"
                >
                  {automationLoading ? 'Arming...' : 'Enable Monitoring'}
                </button>
              </form>

              <div className="space-y-3">
                {automationTargets.length === 0 && (
                  <div className="text-xs text-cyber-dim font-mono border border-dashed border-cyber-dim/30 rounded p-3">
                    No recurring targets armed yet.
                  </div>
                )}
                {automationTargets.map((item) => (
                  <div key={item.id} className="border border-cyber-purple/20 rounded-lg p-3 bg-cyber-bg/40">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-white font-mono">{item.domain}</div>
                        <div className="text-cyber-dim text-xs font-mono mt-1">
                          {item.scan_type} • every {item.interval_minutes} min
                        </div>
                        {item.last_diff && Object.values(item.last_diff).some((value) => Array.isArray(value) && value.length > 0) && (
                          <div className="text-cyber-green text-xs font-mono mt-2">
                            Delta detected: {Object.values(item.last_diff).reduce((sum, value) => sum + (Array.isArray(value) ? value.length : 0), 0)} new artifacts
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => handleToggleMonitoring(item.id, !item.enabled)}
                          className={`px-3 py-1 rounded text-xs font-mono border ${item.enabled ? 'border-cyber-green text-cyber-green bg-cyber-green/10' : 'border-cyber-dim text-cyber-dim bg-cyber-dim/10'}`}
                        >
                          {item.enabled ? 'Enabled' : 'Disabled'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDeleteMonitoring(item.id)}
                          className="p-2 border border-cyber-pink/40 rounded text-cyber-pink hover:bg-cyber-pink/10"
                          title="Delete monitoring target"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeScanId && !isLoading && (
            <button 
              onClick={() => navigate(`/scans/${activeScanId}`)}
              className="w-full mt-4 py-3 bg-cyber-green/20 border border-cyber-green text-cyber-green hover:bg-cyber-green hover:text-cyber-bg font-bold uppercase tracking-widest transition-all duration-300 rounded flex items-center justify-center gap-2"
            >
              View Full Report
            </button>
          )}
        </div>

        <div className="lg:col-span-2">
          <h2 className="text-xl font-mono text-white mb-4 uppercase tracking-wider">Live System Telemetry</h2>
          <TerminalLogs logs={logs} />
        </div>
      </div>
    </div>
  );
}
