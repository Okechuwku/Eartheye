import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { useAuth } from '../context/AuthContext';
import { Lock, User, ShieldAlert } from 'lucide-react';

function formatRegistrationError(err) {
  if (!err.response) {
    return 'Registration failed. Frontend could not reach the API gateway.';
  }

  const detail = err.response.data?.detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const firstIssue = detail[0];
    return firstIssue?.msg || 'Registration failed due to invalid input.';
  }

  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }

  return 'Registration failed. System rejected identity.';
}

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { register } = useAuth();
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (password.length < 12) {
      setError('Password must be at least 12 characters long.');
      return;
    }

    try {
      await register(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError(formatRegistrationError(err));
    }
  };

  return (
    <div className="flex-grow flex items-center justify-center">
      <motion.div 
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="glass-panel p-8 rounded-xl w-full max-w-md relative overflow-hidden"
      >
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-purple to-cyber-pink"></div>
        
        <h2 className="text-3xl font-bold mb-2 text-center text-glow-purple uppercase tracking-widest text-cyber-purple">Initialize</h2>
        <p className="text-cyber-dim text-center mb-8 font-mono text-sm">Create Neural Link Identity</p>
        
        {error && <div className="mb-4 p-3 bg-cyber-pink/10 border border-cyber-pink/30 text-cyber-pink rounded text-sm text-center flex items-center justify-center gap-2"><ShieldAlert className="w-4 h-4"/> {error}</div>}
        
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="relative">
            <User className="absolute left-3 top-3 text-cyber-purple w-5 h-5 pointer-events-none" />
            <input 
              type="email" 
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-cyber-bg/50 border border-cyber-purple/30 text-white pl-10 pr-4 py-3 rounded outline-none focus:border-cyber-purple transition-colors font-mono"
              placeholder="IDENTIFIER (EMAIL)"
            />
          </div>
          
          <div className="relative">
            <Lock className="absolute left-3 top-3 text-cyber-purple w-5 h-5 pointer-events-none" />
            <input 
              type="password" 
              required
              minLength={12}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-cyber-bg/50 border border-cyber-purple/30 text-white pl-10 pr-4 py-3 rounded outline-none focus:border-cyber-purple transition-colors font-mono"
              placeholder="PASSPHRASE"
            />
            <p className="mt-2 text-xs text-cyber-dim font-mono">Use at least 12 characters for your passphrase.</p>
          </div>
          
          <button 
            type="submit" 
            className="w-full py-3 bg-cyber-purple/20 border border-cyber-purple text-cyber-purple hover:bg-cyber-purple hover:text-cyber-bg font-bold uppercase tracking-widest transition-all duration-300 glow-purple rounded mt-4"
          >
            Create Identity
          </button>
        </form>

        <p className="mt-6 text-center text-cyber-dim text-sm font-mono">
          Already verified? <Link to="/login" className="text-cyber-blue hover:text-white transition-colors">Connect here</Link>
        </p>
      </motion.div>
    </div>
  );
}
