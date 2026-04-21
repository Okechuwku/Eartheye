import React from 'react';

export default function TerminalLogs({ logs }) {
  // Determine color based on module
  const getModuleStyle = (moduleName) => {
    switch(moduleName) {
      case 'Discovery': return 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30';
      case 'Crawler':   return 'text-green-400 bg-green-400/10 border-green-400/30';
      case 'JavaScript':return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30';
      case 'GraphQL':   return 'text-purple-400 bg-purple-400/10 border-purple-400/30';
      case 'Secrets':   return 'text-red-400 bg-red-400/10 border-red-400/30';
      case 'SafeVuln':  return 'text-orange-400 bg-orange-400/10 border-orange-400/30';
      default:          return 'text-cyber-blue bg-cyber-blue/10 border-cyber-blue/30';
    }
  };

  const getLevelStyle = (level) => {
    switch(level) {
      case 'error':
      case 'critical': return 'text-red-500 font-bold';
      case 'warn':     return 'text-yellow-500';
      case 'success':  return 'text-green-400';
      default:         return 'text-gray-300';
    }
  };

  return (
    <div className="glass-panel p-4 rounded-lg h-96 overflow-y-auto font-mono text-sm">
      {logs.length === 0 ? (
        <div className="text-cyber-dim italic">Awaiting connection telemetry...</div>
      ) : (
        <div className="space-y-1 pb-4">
          {logs.map((log, i) => {
            // Check if it's a simple string (fallback) or parsed JSON
            if (typeof log === 'string') {
               return <div key={i} className="text-gray-400">{log}</div>;
            }

            // Structured log
            const time = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '...';
            return (
              <div key={i} className="flex items-start gap-3 hover:bg-white/5 p-1 rounded transition-colors break-all">
                <span className="text-cyber-dim/50 whitespace-nowrap">[{time}]</span>
                {log.module && (
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border whitespace-nowrap w-24 text-center ${getModuleStyle(log.module)}`}>
                        {log.module}
                    </span>
                )}
                <span className={`flex-1 ${getLevelStyle(log.level)}`}>
                   {log.message}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function getLogClassName(log) {
  if (log.includes('[ERROR]') || log.includes('[-]')) return 'text-cyber-pink';
  if (log.includes('[+]')) return 'text-cyber-green';
  if (log.includes('[SYSTEM]') || log.includes('[*]')) return 'text-cyber-blue';
  return 'text-cyber-text';
}
