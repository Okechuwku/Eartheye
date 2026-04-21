import React from 'react';
import { motion } from 'framer-motion';
import { Search, Globe, ShieldAlert, CheckCircle, Loader2 } from 'lucide-react';

const STAGES = [
  { id: 'subdomains', label: 'Subdomain Discovery', icon: Search },
  { id: 'endpoints', label: 'Endpoint Crawling', icon: Globe },
  { id: 'vulnerabilities', label: 'Vulnerability Analysis', icon: ShieldAlert },
  { id: 'completed', label: 'Scan Completed', icon: CheckCircle }
];

export default function ScanProgress({ currentStage, logs }) {
  const getStageIndex = (stageId) => STAGES.findIndex(s => s.id === stageId);
  const currentIndex = getStageIndex(currentStage);

  return (
    <div className="w-full bg-cyber-bg/50 border border-cyber-blue/30 rounded-lg p-6 font-mono mb-6">
      <h3 className="text-cyber-green text-sm uppercase mb-4 font-bold tracking-wider flex items-center gap-2">
        <Loader2 className={`w-4 h-4 ${currentIndex < 3 ? 'animate-spin' : 'hidden'}`} />
        Active Operation Status
      </h3>
      
      <div className="flex flex-col md:flex-row justify-between relative">
        {/* Connection Line */}
        <div className="hidden md:block absolute top-5 left-8 right-8 h-0.5 bg-cyber-dim/20 z-0" />
        
        {STAGES.map((stage, index) => {
          const isActive = index === currentIndex;
          const isPast = index < currentIndex;
          const Icon = stage.icon;
          
          let colorClass = 'text-cyber-dim border-cyber-dim/30 bg-cyber-bg';
          if (isActive) colorClass = 'text-cyber-blue border-cyber-blue bg-cyber-blue/10 glow-blue';
          if (isPast) colorClass = 'text-cyber-green border-cyber-green bg-cyber-green/10';

          return (
            <div key={stage.id} className="relative z-10 flex flex-row md:flex-col items-center gap-4 md:gap-2 mb-4 md:mb-0">
              <motion.div 
                initial={{ scale: 0.8 }}
                animate={{ scale: isActive ? 1.1 : 1 }}
                className={`w-10 h-10 rounded-full border-2 flex items-center justify-center transition-colors duration-500 ${colorClass}`}
              >
                <Icon className={`w-5 h-5 ${isActive ? 'animate-pulse' : ''}`} />
              </motion.div>
              <div className="flex flex-col md:items-center">
                <span className={`text-xs uppercase font-bold tracking-wider ${isActive ? 'text-cyber-blue' : isPast ? 'text-cyber-green' : 'text-cyber-dim'}`}>
                  {stage.label}
                </span>
                {isActive && (
                  <span className="text-[10px] text-cyber-blue/70 mt-1 max-w-[120px] text-center hidden md:block truncate">
                    {logs.length > 0 ? logs[logs.length - 1].slice(0, 30) + '...' : 'Initializing...'}
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
