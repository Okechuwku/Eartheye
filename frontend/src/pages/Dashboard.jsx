import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { useNavigate, useLocation } from 'react-router-dom';
import { Activity, ShieldAlert, Target, Play } from 'lucide-react';
import { API_URL } from '../config/api.js';

export default function Dashboard() {
  const [stats, setStats] = useState({
    total_scans: 0,
    active_scans: 0,
    vulnerabilities_found: 0,
    recent_targets: []
  });
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    fetchStats();
    // Redirect to new scan if user came from LandingPage with a target
    if (location.state?.initialTarget) {
      navigate('/scans/new', { state: { target: location.state.initialTarget } });
    }
  }, [location, navigate]);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API_URL}/dashboard/stats`);
      setStats(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white uppercase tracking-widest font-mono">Command Center</h1>
          <p className="text-cyber-dim text-sm mt-1">System status overview</p>
        </div>
        <button 
          onClick={() => navigate('/scans/new')}
          className="flex items-center gap-2 bg-cyber-blue/20 border border-cyber-blue text-cyber-blue px-6 py-3 rounded hover:bg-cyber-blue hover:text-cyber-bg transition-colors font-bold uppercase text-sm glow-blue"
        >
          <Play className="w-4 h-4" /> Initialize Scan
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <StatCard 
          icon={<Target className="w-8 h-8 text-cyber-blue" />}
          title="Total Scans"
          value={stats.total_scans}
          colorClass="border-cyber-blue/30"
          valueClass="text-cyber-blue text-glow-blue"
        />
        <StatCard 
          icon={<Activity className="w-8 h-8 text-cyber-green" />}
          title="Active Operations"
          value={stats.active_scans}
          colorClass="border-cyber-green/30"
          valueClass="text-cyber-green"
        />
        <StatCard 
          icon={<ShieldAlert className="w-8 h-8 text-cyber-pink" />}
          title="Vulnerabilities"
          value={stats.vulnerabilities_found}
          colorClass="border-cyber-pink/30"
          valueClass="text-cyber-pink"
        />
      </div>

      <div className="glass-panel p-6 rounded-lg relative overflow-hidden">
        <div className="absolute top-0 left-0 w-1 h-full bg-cyber-purple"></div>
        <div className="flex justify-between items-center mb-6">
            <h2 className="text-xl font-mono text-white uppercase tracking-wider">Attack Surface Inventory</h2>
            <button className="text-xs text-cyber-blue hover:text-white transition-colors border border-cyber-blue/30 px-3 py-1 rounded">View All Targets</button>
        </div>
        
        {stats.recent_targets.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-sm">
                <thead>
                    <tr className="text-cyber-dim border-b border-cyber-dim/20">
                        <th className="pb-3 px-2 font-normal uppercase tracking-wider">Domain</th>
                        <th className="pb-3 px-2 font-normal uppercase tracking-wider">Endpoints</th>
                        <th className="pb-3 px-2 font-normal uppercase tracking-wider">Vulns</th>
                        <th className="pb-3 px-2 font-normal uppercase tracking-wider">Risk Score</th>
                        <th className="pb-3 px-2 font-normal uppercase tracking-wider">Last Scan</th>
                    </tr>
                </thead>
                <tbody>
                    {stats.recent_targets.map((target, idx) => (
                    <tr key={idx} className="border-b border-cyber-dim/10 hover:bg-white/5 transition-colors cursor-pointer" onClick={() => navigate('/scans/new', {state: {target: target.domain}})}>
                        <td className="py-4 px-2 text-cyber-blue font-bold tracking-wide">{target.domain}</td>
                        <td className="py-4 px-2 text-gray-300">{target.total_endpoints}</td>
                        <td className="py-4 px-2">
                            <span className={target.total_vulnerabilities > 0 ? "text-red-400" : "text-gray-500"}>{target.total_vulnerabilities}</span>
                        </td>
                        <td className="py-4 px-2">
                            <div className="flex items-center gap-2">
                                <div className="w-16 h-2 bg-black/60 rounded overflow-hidden">
                                    <div className={`h-full ${target.risk_score > 70 ? 'bg-red-500 glow-red' : target.risk_score > 30 ? 'bg-yellow-500 glow-yellow' : 'bg-green-500 glow-green'}`} style={{width: `${target.risk_score}%`}}></div>
                                </div>
                                <span className={target.risk_score > 70 ? 'text-red-400 font-bold' : 'text-gray-400'}>{target.risk_score}</span>
                            </div>
                        </td>
                        <td className="py-4 px-2 text-cyber-dim text-xs">
                            {target.last_scan ? new Date(target.last_scan).toLocaleDateString() : 'Pending'}
                            {target.last_change_detected && <span className="ml-2 text-[10px] bg-cyber-pink/20 text-cyber-pink px-1 rounded border border-cyber-pink/40 animate-pulse">CHANGED</span>}
                        </td>
                    </tr>
                    ))}
                </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-10 border border-dashed border-cyber-dim/30 rounded">
            <p className="text-cyber-dim font-mono text-sm">Target inventory is empty. Initialize a new scan to discover assets.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function StatCard({ icon, title, value, colorClass, valueClass }) {
  return (
    <motion.div 
      whileHover={{ y: -5 }}
      className={`glass-panel p-6 rounded-lg border-t-2 ${colorClass}`}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-cyber-dim font-mono text-sm uppercase tracking-wider">{title}</h3>
        {icon}
      </div>
      <div className={`text-4xl font-bold ${valueClass}`}>{value}</div>
    </motion.div>
  );
}
