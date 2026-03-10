import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Eye, Shield, LogOut, Menu } from 'lucide-react';

export default function Navbar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/');
  };

  return (
    <nav className="glass-panel border-b border-cyber-blue/20 px-6 py-4 flex items-center justify-between sticky top-0 z-50">
      <Link to="/" className="flex items-center gap-2 text-cyber-blue hover:text-white transition-colors duration-300">
        <Eye className="w-8 h-8 glow-blue" />
        <span className="font-mono text-xl font-bold tracking-widest text-glow-blue uppercase">Eartheye</span>
      </Link>

      <div className="hidden md:flex items-center gap-6">
        {user ? (
          <>
            <Link to="/dashboard" className="text-cyber-text hover:text-cyber-blue transition-colors font-mono uppercase text-sm">Dashboard</Link>
            {user.role === 'Admin' && (
              <Link to="/admin" className="text-cyber-text hover:text-cyber-purple transition-colors font-mono uppercase text-sm">Admin</Link>
            )}
            <div className="flex items-center gap-4 border-l border-cyber-dim/30 pl-6">
              <span className="text-cyber-dim text-sm">{user.email}</span>
              <button 
                onClick={handleLogout}
                className="text-cyber-pink hover:text-white transition-colors flex items-center gap-1 text-sm font-mono uppercase"
              >
                <LogOut className="w-4 h-4" /> Disconnect
              </button>
            </div>
          </>
        ) : (
          <>
            <Link to="/login" className="text-cyber-text hover:text-cyber-blue transition-colors font-mono uppercase text-sm">Login</Link>
            <Link to="/register" className="px-4 py-2 border border-cyber-blue text-cyber-blue rounded hover:bg-cyber-blue/10 transition-colors font-mono uppercase text-sm glow-blue">Initialize</Link>
          </>
        )}
      </div>
      
      <div className="md:hidden">
        <Menu className="text-cyber-blue w-6 h-6" />
      </div>
    </nav>
  );
}
