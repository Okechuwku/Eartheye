import React, { useState, useEffect, useRef } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import TerminalLogs from '../components/TerminalLogs';
import ScanProgress from '../components/ScanProgress';
import { Target, Zap, Lock } from 'lucide-react';

export default function NewScan() {
  const location = useLocation();
  const navigate = useNavigate();
  const [target, setTarget] = useState(location.state?.target || '');
  const [scanType, setScanType] = useState('Recon Scan');
  const [isLoading, setIsLoading] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [ws, setWs] = useState(null);
  const [currentStage, setCurrentStage] = useState('subdomains');
  const [tierError, setTierError] = useState('');
  
  // Ref to hold the current raw token synchronously for the auth checks
  const token = localStorage.getItem('token');
  const userStr = localStorage.getItem('user');
  const isFreeTier = userStr ? JSON.parse(userStr).subscription_tier === 'Free' && JSON.parse(userStr).role !== 'Admin' : false;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target) return;
    setTierError('');
    setIsLoading(true);
    setLogs([]); 
    setCurrentStage('subdomains');
    try {
      const res = await axios.post(`${API_URL}/scans/`, {
        target_domain: target,
        scan_type: scanType
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      const scanId = res.data.id;
      setActiveScanId(scanId);
      connectWebSocket(scanId);
    } catch (err) {
      console.error(err);
      if (err.response?.status === 403) {
          setTierError("Premium subscription required for advanced operations.");
      } else if (err.response?.status === 429) {
          setTierError(err.response.data.detail || "Rate limit exceeded.");
      } else {
          setLogs(prev => [...prev, { level: 'error', module: 'System', message: `API Error: ${err.message}` }]);
      }
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
    
    socket.onopen = () => setLogs([{ module: 'System', level: 'info', message: 'Secure neural link established. Waiting for scanner engine...' }]);
    
    socket.onmessage = (event) => {
      try {
          const payload = JSON.parse(event.data);
          
          if (payload.type === 'log') {
              setLogs(prev => [...prev, payload]);
          } else if (payload.type === 'event') {
              // Map module events to the ScanProgress UI stages
              if (payload.event === 'module_start') {
                  if (payload.module === 'Discovery') setCurrentStage('subdomains');
                  else if (payload.module === 'Crawler') setCurrentStage('endpoints');
                  else if (payload.module === 'JavaScript' || payload.module === 'GraphQL' || payload.module === 'Secrets') setCurrentStage('endpoints');
                  else if (payload.module === 'SafeVuln') setCurrentStage('vulnerabilities');
              } else if (payload.event === 'scan_complete') {
                  setCurrentStage('completed');
                  setIsLoading(false);
                  socket.close();
              } else if (payload.event === 'scan_failed') {
                  setIsLoading(false);
                  socket.close();
              }
          }
      } catch (e) {
          // Fallback if structured JSON parsing fails
          setLogs(prev => [...prev, event.data]);
      }
    };
    
    socket.onerror = () => {
      setLogs(prev => [...prev, { module: 'System', level: 'error', message: 'WebSocket connection interrupted.' }]);
      setIsLoading(false);
    };

    setWs(socket);
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
          <br/><span className="text-cyber-dim italic mt-2 inline-block">Ensure you have explicit authorization before initiating a scan.</span>
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
            
            {tierError && (
                <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-3 rounded text-sm font-mono">
                    {tierError}
                </div>
            )}

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
              <div className="relative">
                  <select 
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value)}
                    className="w-full bg-cyber-bg/50 border border-cyber-purple/30 text-white px-4 py-3 rounded outline-none focus:border-cyber-purple transition-colors font-mono appearance-none"
                    disabled={isLoading}
                  >
                    <option value="Basic Scan">Basic Scan (Subdomains Only)</option>
                    <option value="Recon Scan" disabled={isFreeTier}>Recon Scan (Subdomains + Discovery)</option>
                    <option value="Full Scan" disabled={isFreeTier}>Full Scan (Recon + Triage)</option>
                  </select>
                  {isFreeTier && (scanType === 'Recon Scan' || scanType === 'Full Scan') && (
                      <Lock size={14} className="absolute right-8 top-4 text-cyber-dim" />
                  )}
              </div>
              {isFreeTier && (
                  <p className="text-xs text-cyber-pink mt-2 font-mono flex items-center gap-1">
                      <Lock size={12}/> Premium features are locked.
                  </p>
              )}
            </div>

            <button 
              type="submit" 
              disabled={isLoading || !target || (isFreeTier && scanType !== 'Basic Scan')}
              className={`w-full py-3 flex items-center justify-center gap-2 font-bold uppercase tracking-widest transition-all duration-300 rounded ${isLoading || (isFreeTier && scanType !== 'Basic Scan') ? 'bg-cyber-dim/20 text-cyber-dim border border-cyber-dim cursor-not-allowed' : 'bg-cyber-blue/20 border border-cyber-blue text-cyber-blue hover:bg-cyber-blue hover:text-cyber-bg glow-blue'}`}
            >
              <Zap className="w-5 h-5" /> 
              {isLoading ? 'Scanning...' : 'Execute'}
            </button>
          </form>

          {activeScanId && !isLoading && currentStage === 'completed' && (
            <button 
              onClick={() => navigate(`/scans/${activeScanId}`)}
              className="w-full mt-4 py-3 bg-cyber-green/20 border border-cyber-green text-cyber-green hover:bg-cyber-green hover:text-cyber-bg font-bold uppercase tracking-widest transition-all duration-300 rounded flex items-center justify-center gap-2 animate-pulse"
            >
              View Full Report
            </button>
          )}
        </div>

        <div className="lg:col-span-2">
          {activeScanId && (
            <ScanProgress currentStage={currentStage} />
          )}
          <h2 className="text-xl font-mono text-white mt-8 mb-4 uppercase tracking-wider">Live System Telemetry</h2>
          <TerminalLogs logs={logs} />
        </div>
      </div>
    </div>
  );
}
