import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Shield, Users, Activity } from 'lucide-react';

export default function AdminPanel() {
  const [users, setUsers] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAdminData = async () => {
      try {
        const [usersRes, scansRes] = await Promise.all([
          axios.get('http://localhost:8000/api/admin/users'),
          axios.get('http://localhost:8000/api/admin/scans')
        ]);
        setUsers(usersRes.data);
        setScans(scansRes.data);
        setLoading(false);
      } catch (err) {
        console.error(err);
        setLoading(false);
      }
    };
    fetchAdminData();
  }, []);

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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="glass-panel p-6 rounded-lg relative overflow-hidden h-96 flex flex-col">
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
                  <th className="pb-2">Clearance Level</th>
                </tr>
              </thead>
              <tbody>
                {users.map(u => (
                  <tr key={u.id} className="border-b border-cyber-dim/10 hover:bg-cyber-blue/5 transition-colors">
                    <td className="py-3 text-cyber-dim">#{u.id}</td>
                    <td className="py-3 text-white">{u.email}</td>
                    <td className="py-3">
                      <span className={`px-2 py-1 rounded text-xs ${u.role === 'Admin' ? 'bg-cyber-purple/20 text-cyber-purple border border-cyber-purple/50' : 'bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/30'}`}>
                        {u.role}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-panel p-6 rounded-lg relative overflow-hidden h-96 flex flex-col">
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
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
