import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { Lock, User } from 'lucide-react';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();
  
  const message = location.state?.message;

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError('Invalid credentials or neural link failure.');
    }
  };

  return (
    <div className="flex-grow flex items-center justify-center">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass-panel p-8 rounded-xl w-full max-w-md relative overflow-hidden"
      >
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-blue to-cyber-purple"></div>
        
        <h2 className="text-3xl font-bold mb-2 text-center text-glow-blue uppercase tracking-widest">Connect</h2>
        <p className="text-cyber-dim text-center mb-8 font-mono text-sm">Initialize Neural Link Authentication</p>
        
        {message && <div className="mb-4 p-3 bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue rounded text-sm text-center">{message}</div>}
        {error && <div className="mb-4 p-3 bg-cyber-pink/10 border border-cyber-pink/30 text-cyber-pink rounded text-sm text-center">{error}</div>}
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="relative">
            <User className="absolute left-3 top-3 text-cyber-blue w-5 h-5 pointer-events-none" />
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-cyber-bg/50 border border-cyber-blue/30 text-white pl-10 pr-4 py-3 rounded outline-none focus:border-cyber-blue transition-colors font-mono"
              placeholder="IDENTIFIER (EMAIL)"
            />
          </div>
          
          <div className="relative">
            <Lock className="absolute left-3 top-3 text-cyber-blue w-5 h-5 pointer-events-none" />
            <input 
              type="password" 
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-cyber-bg/50 border border-cyber-blue/30 text-white pl-10 pr-4 py-3 rounded outline-none focus:border-cyber-blue transition-colors font-mono"
              placeholder="PASSPHRASE"
            />
          </div>
          
          <button 
            type="submit" 
            className="w-full py-3 bg-cyber-blue/20 border border-cyber-blue text-cyber-blue hover:bg-cyber-blue hover:text-cyber-bg font-bold uppercase tracking-widest transition-all duration-300 glow-blue rounded mt-4"
          >
            Authenticate
          </button>
        </form>

        <p className="mt-6 text-center text-cyber-dim text-sm font-mono">
          No active connection? <Link to="/register" className="text-cyber-purple hover:text-white transition-colors">Initialize here</Link>
        </p>
      </motion.div>
    </div>
  );
}
