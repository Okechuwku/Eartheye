import React, { useEffect, useRef } from 'react';

export default function TerminalLogs({ logs }) {
  const endOfMessagesRef = useRef(null);

  useEffect(() => {
    endOfMessagesRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="bg-[#050508] border border-cyber-blue/30 rounded-lg font-mono text-sm text-cyber-green h-96 flex flex-col mt-6 relative overflow-hidden glass-panel">
      <div className="w-full h-8 bg-cyber-panel flex items-center px-4 border-b border-cyber-blue/20 flex-shrink-0">
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-cyber-pink"></div>
          <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
          <div className="w-3 h-3 rounded-full bg-cyber-green"></div>
        </div>
        <span className="ml-4 text-cyber-dim text-xs select-none">root@eartheye:~#</span>
      </div>
      <div className="p-4 overflow-y-auto flex-grow space-y-1">
        {logs.map((log, idx) => (
          <div key={idx} className="break-all whitespace-pre-wrap">
            {log}
          </div>
        ))}
        {logs.length === 0 && <div className="text-cyber-dim opacity-50 italic animate-pulse">Awaiting neural transmission...</div>}
        <div ref={endOfMessagesRef} />
      </div>
    </div>
  );
}
