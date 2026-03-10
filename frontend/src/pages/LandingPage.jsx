import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Shield, Target, Zap, Activity } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function LandingPage() {
  const [target, setTarget] = useState('');
  const navigate = useNavigate();
  const { user } = useAuth();

  const handleScanStart = (e) => {
    e.preventDefault();
    if (!target) return;
    if (user) {
      navigate('/dashboard', { state: { initialTarget: target } });
    } else {
      navigate('/login', { state: { message: 'Initialize neural link to start scanning' } });
    }
  };

  return (
    <div className="flex flex-col items-center justify-center pt-20 pb-10">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.8 }}
        className="text-center w-full max-w-4xl px-4"
      >
        <h1 className="text-5xl md:text-7xl font-black mb-6 tracking-tighter uppercase">
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyber-blue to-cyber-purple glow-blue">Eartheye</span>
          <br/>
          <span className="text-3xl md:text-4xl text-cyber-text font-light tracking-widest mt-4 block">AI Security Intelligence</span>
        </h1>
        
        <p className="text-xl md:text-2xl text-cyber-dim mb-12 font-mono">
          See your website through the eyes of artificial intelligence.
        </p>

        <form onSubmit={handleScanStart} className="flex max-w-2xl mx-auto mb-20 relative">
          <div className="absolute -inset-1 bg-gradient-to-r from-cyber-blue to-cyber-purple blur opacity-30 group-hover:opacity-100 transition duration-1000 group-hover:duration-200"></div>
          <div className="relative flex w-full">
            <input 
              type="text" 
              placeholder="Enter target website (e.g., example.com)" 
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full bg-cyber-bg/80 border border-cyber-blue/30 text-white px-6 py-4 rounded-l-lg outline-none focus:border-cyber-blue font-mono text-lg backdrop-blur-sm"
            />
            <button 
              type="submit"
              className="bg-cyber-blue/20 border border-cyber-blue border-l-0 text-cyber-blue font-bold px-8 rounded-r-lg hover:bg-cyber-blue hover:text-cyber-bg transition-all duration-300 uppercase tracking-wider glow-blue"
            >
              Start Scan
            </button>
          </div>
        </form>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 text-left mt-24">
          <FeatureCard 
            icon={<Target className="w-8 h-8 text-cyber-blue" />}
            title="Attack Surface Mapping"
            desc="Automatically discover subdomains, open ports, and infrastructure endpoints."
          />
          <FeatureCard 
            icon={<Zap className="w-8 h-8 text-cyber-purple" />}
            title="Automated Reconnaissance"
            desc="Continuous AI-driven reconnaissance engine detecting assets in real-time."
          />
          <FeatureCard 
            icon={<Activity className="w-8 h-8 text-cyber-pink" />}
            title="Vulnerability Detection"
            desc="Identify misconfigurations and vulnerabilities across your perimeter."
          />
          <FeatureCard 
            icon={<Shield className="w-8 h-8 text-cyber-green" />}
            title="Professional Pentesting"
            desc="Export findings seamlessly for integration into security reporting workflows."
          />
        </div>
      </motion.div>
    </div>
  );
}

function FeatureCard({ icon, title, desc }) {
  return (
    <motion.div 
      whileHover={{ y: -5 }}
      className="glass-panel p-6 rounded-lg glass-panel-hover"
    >
      <div className="mb-4">{icon}</div>
      <h3 className="text-xl font-bold mb-2 text-white">{title}</h3>
      <p className="text-cyber-dim text-sm leading-relaxed">{desc}</p>
    </motion.div>
  );
}
