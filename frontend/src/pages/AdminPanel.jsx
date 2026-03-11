import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Activity, Crown, Download, KeyRound, Shield, ShieldAlert, Trash2, Users } from 'lucide-react';
import { roleBadge } from '../utils/roles.js';
import { API_URL } from '../config/api.js';

const ROLE_OPTIONS = ['Free', 'Premium', 'Administrator'];

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
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [secrets, setSecrets] = useState([]);
  const [loading, setLoading] = useState(true);

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

  const updateSubscription = async (userId, role) => {
    try {
      await axios.patch(`${API_URL}/admin/users/${userId}/subscription`, {
        role,
        subscription_status: 'active',
      });
      await fetchAdminData();
    } catch (err) {
      console.error(err);
    }
  };

  const deleteScan = async (scanId) => {
    try {
      await axios.delete(`${API_URL}/admin/scans/${scanId}`);
      await fetchAdminData();
    } catch (err) {
      console.error(err);
    }
  };

  const downloadReport = async (scanId) => {
    try {
      const response = await axios.get(`${API_URL}/admin/scans/${scanId}/report`, {
        responseType: 'blob',
      });
      const contentDisposition = response.headers['content-disposition'] || '';
      const fileNameMatch = contentDisposition.match(/filename\*?=(?:UTF-8''|\")?([^\";]+)/i);
      const fileName = fileNameMatch ? decodeURIComponent(fileNameMatch[1].replace(/\"/g, '')) : `scan-${scanId}-report.txt`;
      const blobUrl = window.URL.createObjectURL(new Blob([response.data], { type: 'text/plain' }));
      const link = document.createElement('a');
      link.href = blobUrl;
      link.download = fileName;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(blobUrl);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) return <div className="text-cyber-purple font-mono p-10">Accessing secure mainframe...</div>;

  return (
    <div className="w-full max-w-7xl mx-auto py-8">
      <div className="flex items-center gap-3 mb-8 border-b border-cyber-purple/30 pb-4">
        <Shield className="w-8 h-8 text-cyber-purple glow-purple" />
        <div>
          <h1 className="text-3xl font-bold text-white uppercase tracking-widest font-mono">System Oversight Protocol</h1>
          <p className="text-cyber-purple text-sm mt-1 font-mono uppercase">Level 5 Clearance Granted</p>
        </div>
      </div>

      <div className="grid grid-cols-2 xl:grid-cols-6 gap-4 mb-8">
        <MetricCard icon={<Users className="w-5 h-5 text-cyber-blue" />} label="Users" value={overview.total_users} />
        <MetricCard icon={<Activity className="w-5 h-5 text-cyber-green" />} label="Scans" value={overview.total_scans} />
        <MetricCard icon={<ShieldAlert className="w-5 h-5 text-cyber-pink" />} label="Vulns" value={overview.total_vulnerabilities} />
        <MetricCard icon={<KeyRound className="w-5 h-5 text-yellow-400" />} label="Secrets" value={overview.total_secrets} />
        <MetricCard icon={<Crown className="w-5 h-5 text-cyber-purple" />} label="Premium" value={overview.premium_users} />
        <MetricCard icon={<Activity className="w-5 h-5 text-cyber-blue" />} label="Monitors" value={overview.active_monitors} />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden h-[28rem] flex flex-col">
          <div className="absolute top-0 left-0 w-1 h-full bg-cyber-blue"></div>
          <h2 className="text-xl font-mono text-white mb-6 uppercase tracking-wider flex items-center gap-2">
            <Users className="text-cyber-blue h-5 w-5" /> Registered Identities
          </h2>
          <div className="overflow-y-auto pr-2 flex-grow">
            <table className="w-full text-left font-mono text-sm">
              <thead className="text-cyber-dim border-b border-cyber-dim/30">
                <tr>
                  <th className="pb-2">ID</th>
                  <th className="pb-2">Identifier</th>
                  <th className="pb-2">Plan</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} className="border-b border-cyber-dim/10 hover:bg-cyber-blue/5 transition-colors">
                    <td className="py-3 text-cyber-dim">#{u.id}</td>
                    <td className="py-3 text-white">{u.email}</td>
                    <td className="py-3">
                      <select
                        value={u.role}
                        onChange={(e) => updateSubscription(u.id, e.target.value)}
                        className="bg-cyber-bg/60 border border-cyber-blue/20 text-white rounded px-3 py-2 text-xs font-mono outline-none"
                      >
                        {ROLE_OPTIONS.map((role) => (
                          <option key={role} value={role}>{role}</option>
                        ))}
                      </select>
                      <div className="text-[10px] text-cyber-dim font-mono mt-1 uppercase tracking-widest">{roleBadge(u.role)}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-panel p-6 rounded-lg relative overflow-hidden h-[28rem] flex flex-col">
          <div className="absolute top-0 left-0 w-1 h-full bg-cyber-green"></div>
          <h2 className="text-xl font-mono text-white mb-6 uppercase tracking-wider flex items-center gap-2">
            <Activity className="text-cyber-green h-5 w-5" /> Global Operations
          </h2>
          <div className="overflow-y-auto pr-2 flex-grow">
            <table className="w-full text-left font-mono text-sm">
              <thead className="text-cyber-dim border-b border-cyber-dim/30">
                <tr>
                  <th className="pb-2">Target</th>
                  <th className="pb-2">Type</th>
                  <th className="pb-2">Status</th>
                  <th className="pb-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.id} className="border-b border-cyber-dim/10 hover:bg-cyber-green/5 transition-colors">
                    <td className="py-3 text-white">{s.target_domain}</td>
                    <td className="py-3 text-cyber-dim">{s.scan_type}</td>
                    <td className="py-3">
                      <span className={`text-xs ${s.status === 'Running' ? 'text-cyber-green animate-pulse' : s.status === 'Completed' ? 'text-cyber-blue' : 'text-cyber-pink'}`}>
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => downloadReport(s.id)}
                          className="p-2 rounded border border-cyber-blue/30 text-cyber-blue hover:bg-cyber-blue/10"
                          title="Download report"
                        >
                          <Download className="w-4 h-4" />
                        </button>
                        <button
                          onClick={() => deleteScan(s.id)}
                          className="p-2 rounded border border-cyber-pink/30 text-cyber-pink hover:bg-cyber-pink/10"
                          title="Delete scan"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
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
