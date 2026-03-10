import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import axios from 'axios';
import TerminalLogs from '../components/TerminalLogs';
import { Target, Zap } from 'lucide-react';

export default function NewScan() {
  const location = useLocation();
  const [target, setTarget] = useState(location.state?.target || '');
  const [scanType, setScanType] = useState('Recon Scan');
  const [isLoading, setIsLoading] = useState(false);
  const [activeScanId, setActiveScanId] = useState(null);
  const [logs, setLogs] = useState([]);
  const [ws, setWs] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target) return;
    setIsLoading(true);
    setLogs([]); // Reset logs
    try {
      const res = await axios.post('http://localhost:8000/api/scans/', {
        target_domain: target,
        scan_type: scanType
      });
      
      const scanId = res.data.id;
      setActiveScanId(scanId);
      connectWebSocket(scanId);
    } catch (err) {
      console.error(err);
      setLogs((prev) => [...prev, `[ERROR] Failed to initialize scan: ${err.message}`]);
      setIsLoading(false);
    }
  };

  const connectWebSocket = (scanId) => {
    const socket = new WebSocket(`ws://localhost:8000/ws/scan/${scanId}`);
    
    socket.onopen = () => setLogs((prev) => [...prev, '[SYSTEM] Secure neural link established. Waiting for scanner engine...']);
    
    socket.onmessage = (event) => {
      setLogs((prev) => [...prev, event.data]);
      if (event.data.includes("Results saved to database")) {
        setIsLoading(false);
        socket.close();
      }
    };
    
    socket.onerror = (error) => {
      setLogs((prev) => [...prev, `[ERROR] WebSocket connection failed.`]);
      setIsLoading(false);
    };

    socket.onclose = () => {
      if (isLoading) {
         setLogs((prev) => [...prev, '[SYSTEM] Connection terminated unexpectedly.']);
         setIsLoading(false);
      }
    };

    setWs(socket);
  };

  useEffect(() => {
    return () => {
      if (ws) ws.close();
    };
  }, [ws]);

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
                <option value="Basic Scan">Basic Scan (Subdomains Only)</option>
                <option value="Recon Scan">Recon Scan (Subdomains + Discovery)</option>
                <option value="Full Scan">Full Scan (Recon + Vulnerabilities)</option>
              </select>
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

          {activeScanId && !isLoading && (
            <button 
              onClick={() => window.location.href = `/scans/${activeScanId}`}
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
