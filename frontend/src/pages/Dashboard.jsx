import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { useNavigate, useLocation } from 'react-router-dom';
import { Activity, ShieldAlert, Target, Play } from 'lucide-react';

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
      const res = await axios.get('http://localhost:8000/api/dashboard/stats');
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
        <h2 className="text-xl font-mono text-white mb-6 uppercase tracking-wider">Recent Operational Targets</h2>
        
        {stats.recent_targets.length > 0 ? (
          <div className="space-y-4">
            {stats.recent_targets.map((target, idx) => (
              <div key={idx} className="flex items-center justify-between p-4 bg-cyber-panel/50 border border-cyber-dim/20 rounded hover:border-cyber-blue/40 transition-colors">
                <span className="font-mono text-cyber-blue">{target}</span>
                <span className="text-xs text-cyber-dim uppercase font-mono tracking-widest">Logged</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-10 border border-dashed border-cyber-dim/30 rounded">
            <p className="text-cyber-dim font-mono text-sm">No historical data available. System idle.</p>
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
