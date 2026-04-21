import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Shield, Users, Activity, Trash2, ArrowUpCircle, Award } from 'lucide-react';

export default function AdminPanel() {
  const [overview, setOverview] = useState({
    total_users: 0,
    total_scans: 0,
    total_vulnerabilities: 0,
    total_secrets: 0,
    premium_users: 0,
    active_monitors: 0,
  });
  const [users, setUsers] = useState([]);
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const token = localStorage.getItem('token');
  const headers = { Authorization: `Bearer ${token}` };

  const fetchAdminData = async () => {
    try {
      const [usersRes, scansRes, statsRes] = await Promise.all([
        axios.get('http://localhost:8000/api/admin/users', { headers }),
        axios.get('http://localhost:8000/api/admin/scans', { headers }),
        axios.get('http://localhost:8000/api/admin/stats', { headers })
      ]);
      setUsers(usersRes.data);
      setScans(scansRes.data);
      setStats(statsRes.data);
      setLoading(false);
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  };

  const fetchAdminData = async () => {
    try {
      const [overviewRes, usersRes, scansRes, vulnerabilitiesRes, secretsRes] = await Promise.all([
        axios.get(`${API_URL}/admin/overview`),
        axios.get(`${API_URL}/admin/users`),
        axios.get(`${API_URL}/admin/scans`),
        axios.get(`${API_URL}/admin/vulnerabilities`),
        axios.get(`${API_URL}/admin/secrets`),
      ]);
      setOverview(overviewRes.data);
      setUsers(usersRes.data);
      setScans(scansRes.data);
      setVulnerabilities(vulnerabilitiesRes.data);
      setSecrets(secretsRes.data);
      setLoading(false);
    } catch (err) {
      console.error(err);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, []);

  const handleTierToggle = async (userId, currentTier) => {
      const newTier = currentTier === 'Free' ? 'Premium' : 'Free';
      try {
          await axios.patch(`http://localhost:8000/api/admin/users/${userId}/tier`, 
              { subscription_tier: newTier }, { headers });
          fetchAdminData();
      } catch (err) { console.error(err); }
  };

  const handleRoleToggle = async (userId, currentRole) => {
      const newRole = currentRole === 'User' ? 'Admin' : 'User';
      try {
          await axios.patch(`http://localhost:8000/api/admin/users/${userId}/role`, 
              { role: newRole }, { headers });
          fetchAdminData();
      } catch (err) { alert(err.response?.data?.detail || "Error updating role"); }
  };

  const handleDeleteScan = async (scanId) => {
      if(!window.confirm(`Delete scan ${scanId} forever?`)) return;
      try {
          await axios.delete(`http://localhost:8000/api/admin/scans/${scanId}`, { headers });
          fetchAdminData();
      } catch (err) { console.error(err); }
  };

  if (loading) return <div className="text-cyber-purple font-mono p-10">Accessing secure mainframe...</div>;

  return (
    <div className="w-full max-w-7xl mx-auto py-8 px-4">
      <div className="flex items-center gap-3 mb-8 border-b border-cyber-purple/30 pb-4">
        <Shield className="w-8 h-8 text-cyber-purple glow-purple" />
        <div>
          <h1 className="text-3xl font-bold text-white uppercase tracking-widest font-mono">System Oversight Protocol</h1>
          <p className="text-cyber-purple text-sm mt-1 font-mono uppercase">Level 5 Clearance Granted</p>
        </div>
      </div>

      {stats && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8 font-mono">
              <div className="glass-panel p-4 rounded text-center border-t-2 border-cyber-blue">
                  <div className="text-3xl text-white font-bold">{stats.total_users}</div>
                  <div className="text-xs text-cyber-blue uppercase tracking-widest mt-1">Total Identities</div>
              </div>
              <div className="glass-panel p-4 rounded text-center border-t-2 border-yellow-500">
                  <div className="text-3xl text-yellow-500 font-bold">{stats.premium_users}</div>
                  <div className="text-xs text-yellow-500/70 uppercase tracking-widest mt-1">Premium Accounts</div>
              </div>
              <div className="glass-panel p-4 rounded text-center border-t-2 border-cyber-green">
                  <div className="text-3xl text-cyber-green font-bold">{stats.total_scans}</div>
                  <div className="text-xs text-cyber-green/70 uppercase tracking-widest mt-1">Operations Run</div>
              </div>
              <div className="glass-panel p-4 rounded text-center border-t-2 border-cyber-pink">
                  <div className="text-3xl text-cyber-pink font-bold">{stats.total_vulnerabilities}</div>
                  <div className="text-xs text-cyber-pink/70 uppercase tracking-widest mt-1">Risks Flagged</div>
              </div>
          </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        
        {/* USERS TABLE */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden h-[500px] flex flex-col border border-cyber-blue/20">
          <div className="absolute top-0 left-0 w-1 h-full bg-cyber-blue"></div>
          <h2 className="text-xl font-mono text-white mb-6 uppercase tracking-wider flex items-center gap-2">
            <Users className="text-cyber-blue h-5 w-5" /> Registered Identities
          </h2>
          <div className="overflow-y-auto pr-2 flex-grow custom-scrollbar">
            <table className="w-full text-left font-mono text-sm">
              <thead className="text-cyber-dim border-b border-cyber-dim/30">
                <tr>
                  <th className="pb-2 w-12">ID</th>
                  <th className="pb-2">Identifier</th>
                  <th className="pb-2 w-24">Clearance</th>
                  <th className="pb-2 w-24">Tier</th>
                  <th className="pb-2 text-right w-20">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-dim/10">
                {users.map(u => (
                  <tr key={u.id} className="hover:bg-cyber-blue/5 transition-colors group">
                    <td className="py-3 text-cyber-dim">#{u.id}</td>
                    <td className="py-3 text-gray-300 truncate max-w-[150px]" title={u.email}>{u.email}</td>
                    <td className="py-3">
                      <button onClick={() => handleRoleToggle(u.id, u.role)} className={`px-2 py-0.5 rounded text-xs transition-colors ${u.role === 'Admin' ? 'bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/50 hover:bg-cyber-purple hover:text-white' : 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/30 hover:bg-cyber-blue hover:text-white'}`}>
                        {u.role.toUpperCase()}
                      </button>
                    </td>
                    <td className="py-3">
                      <button onClick={() => handleTierToggle(u.id, u.subscription_tier)} className={`px-2 py-0.5 rounded text-xs flex items-center gap-1 transition-colors ${u.subscription_tier === 'Premium' ? 'bg-yellow-500/20 text-yellow-500 border border-yellow-500/50 hover:bg-yellow-500 hover:text-black' : 'bg-gray-800 text-gray-400 border border-gray-600 hover:bg-gray-700'}`}>
                        {u.subscription_tier === 'Premium' && <Award size={10}/>} {u.subscription_tier.toUpperCase()}
                      </button>
                    </td>
                    <td className="py-3 text-right">
                       {/* Actions if needed */}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* SCANS TABLE */}
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden h-[500px] flex flex-col border border-cyber-green/20">
          <div className="absolute top-0 left-0 w-1 h-full bg-cyber-green"></div>
          <h2 className="text-xl font-mono text-white mb-6 uppercase tracking-wider flex items-center gap-2">
            <Activity className="text-cyber-green h-5 w-5" /> Global Operations
          </h2>
          <div className="overflow-y-auto pr-2 flex-grow custom-scrollbar">
            <table className="w-full text-left font-mono text-sm border-collapse">
              <thead className="text-cyber-dim border-b border-cyber-dim/30 sticky top-0 bg-[#0a0f16]">
                <tr>
                  <th className="pb-2 w-12">ID</th>
                  <th className="pb-2">Target</th>
                  <th className="pb-2 w-24">Type</th>
                  <th className="pb-2 w-24">Status</th>
                  <th className="pb-2 text-right w-12">Delete</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-dim/10">
                {scans.map(s => (
                  <tr key={s.id} className="hover:bg-cyber-green/5 transition-colors">
                    <td className="py-3 text-cyber-dim">#{s.id}</td>
                    <td className="py-3 text-gray-300 truncate max-w-[120px]" title={s.target_domain}>{s.target_domain}</td>
                    <td className="py-3 text-cyber-dim text-xs uppercase">{s.scan_type}</td>
                    <td className="py-3">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${s.status === 'Running' || s.status === 'Pending' ? 'bg-cyber-green/20 text-cyber-green border border-cyber-green/30 animate-pulse' : s.status === 'Completed' ? 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/30' : 'bg-cyber-pink/20 text-cyber-pink border border-cyber-pink/30'}`}>
                        {s.status}
                      </span>
                    </td>
                    <td className="py-3 text-right">
                        <button onClick={() => handleDeleteScan(s.id)} className="text-gray-500 hover:text-red-500 transition-colors p-1">
                            <Trash2 size={16} />
                        </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8 mt-8">
        <AdminFeed
          title="Vulnerability Feed"
          accent="bg-cyber-pink"
          icon={<ShieldAlert className="text-cyber-pink h-5 w-5" />}
          items={vulnerabilities.map((item) => ({
            id: item.id,
            title: `${item.target_domain} • ${item.description}`,
            subtitle: `${item.tool} • ${item.matched_at || 'scan-wide'}`,
            badge: item.severity,
          }))}
          emptyLabel="No vulnerabilities logged across the fleet."
        />

        <AdminFeed
          title="Secret Feed"
          accent="bg-yellow-400"
          icon={<KeyRound className="text-yellow-400 h-5 w-5" />}
          items={secrets.map((item) => ({
            id: item.id,
            title: `${item.target_domain} • ${item.category}`,
            subtitle: `${item.location} • ${item.value_preview || 'redacted'}`,
            badge: item.severity,
          }))}
          emptyLabel="No JavaScript secrets have been flagged."
        />
      </div>
    </div>
  );
}

function MetricCard({ icon, label, value }) {
  return (
    <div className="glass-panel rounded-lg p-4 border border-cyber-blue/10">
      <div className="flex items-center justify-between text-cyber-dim font-mono text-xs uppercase tracking-[0.3em]">
        <span>{label}</span>
        {icon}
      </div>
      <div className="mt-3 text-3xl font-bold text-white">{value}</div>
    </div>
  );
}

function AdminFeed({ title, accent, icon, items, emptyLabel }) {
  return (
    <div className="glass-panel p-6 rounded-lg relative overflow-hidden min-h-[20rem] flex flex-col">
      <div className={`absolute top-0 left-0 w-1 h-full ${accent}`}></div>
      <h2 className="text-xl font-mono text-white mb-6 uppercase tracking-wider flex items-center gap-2">
        {icon} {title}
      </h2>
      <div className="overflow-y-auto pr-2 flex-grow space-y-3">
        {items.length === 0 && (
          <div className="text-cyber-dim font-mono text-sm border border-dashed border-cyber-dim/30 rounded p-4">
            {emptyLabel}
          </div>
        )}
        {items.map((item) => (
          <div key={item.id} className="p-4 bg-cyber-panel/40 border border-cyber-dim/15 rounded-lg">
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-white font-mono text-sm break-all">{item.title}</div>
                <div className="text-cyber-dim font-mono text-xs mt-1 break-all">{item.subtitle}</div>
              </div>
              <span className="px-2 py-1 rounded border border-cyber-blue/20 text-cyber-blue bg-cyber-blue/10 text-[10px] uppercase tracking-widest font-mono">
                {item.badge}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
