import React, { useEffect, useState } from 'react';
import { ShieldAlert, Cpu, Zap, Activity, CheckCircle2, XCircle } from 'lucide-react';

interface HeaderProps {
  latestLatencyMs: number | null;
}

export const Header: React.FC<HeaderProps> = ({ latestLatencyMs }) => {
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [llmOnline, setLlmOnline] = useState<boolean>(false);
  const [currentTime, setCurrentTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      setCurrentTime(new Date().toLocaleTimeString('en-US', { hour12: false }));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const checkConnection = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/');
        if (res.ok) {
          setIsConnected(true);
        } else {
          setIsConnected(false);
        }
      } catch {
        setIsConnected(false);
      }
      
      try {
        const llmRes = await fetch('http://127.0.0.1:8000/status/llm');
        if (llmRes.ok) {
          const data = await llmRes.json();
          setLlmOnline(data.status === 'online');
        } else {
          setLlmOnline(false);
        }
      } catch {
        setLlmOnline(false);
      }
    };
    checkConnection();
    const connInterval = setInterval(checkConnection, 5000);
    return () => clearInterval(connInterval);
  }, []);

  const getLatencyBadgeClass = (latency: number | null) => {
    if (latency === null) return 'bg-slate-800/80 text-slate-400 border-slate-700';
    if (latency < 200) return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 glow-emerald';
    if (latency <= 500) return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    return 'bg-rose-500/10 text-rose-400 border-rose-500/30 glow-rose';
  };

  return (
    <header className="cyber-glass border-b border-slate-800/80 px-6 py-4 sticky top-0 z-50">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Title / Brand */}
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 rounded-xl shadow-lg glow-cyan">
            <ShieldAlert className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-xl font-bold bg-gradient-to-r from-slate-100 via-cyan-100 to-cyan-400 bg-clip-text text-transparent drop-shadow-md">
                AgentSOC
              </h1>
              <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-500/40 font-mono shadow-[0_0_10px_rgba(6,182,212,0.2)]">
                v3.5-GAUNTLET
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-mono tracking-wide mt-0.5">Sub-5ms Telemetry Mitigation Pipeline</p>
          </div>
        </div>

        {/* Status Indicators */}
        <div className="flex items-center space-x-3 md:space-x-4">
          {/* Backend Connection Status */}
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono">
            {isConnected ? (
              <>
                <CheckCircle2 className="w-4 h-4 text-emerald-400 animate-pulse" />
                <span className="text-emerald-400 font-semibold">FastAPI Connected</span>
              </>
            ) : (
              <>
                <XCircle className="w-4 h-4 text-rose-400" />
                <span className="text-rose-400 font-semibold">Backend Offline</span>
              </>
            )}
          </div>

          {/* SLA Latency Badge */}
          <div className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all duration-300 ${getLatencyBadgeClass(latestLatencyMs)}`}>
            <Zap className="w-4 h-4" />
            <span>SLA:</span>
            <span className="font-bold">
              {latestLatencyMs !== null ? `${latestLatencyMs.toFixed(1)}ms` : '-- ms'}
            </span>
          </div>

          {/* Model Status Badge */}
          <div className={`hidden lg:flex items-center space-x-2 px-3 py-1.5 rounded-lg border text-xs font-mono transition-colors ${
            llmOnline 
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' 
              : 'bg-slate-900/80 border-slate-700/50 text-slate-500'
          }`}>
            <Cpu className="w-4 h-4" />
            <span>{llmOnline ? 'LM Studio Connected' : 'LM Studio Offline'}</span>
          </div>

          {/* Live Clock */}
          <div className="hidden sm:flex items-center space-x-1.5 text-xs text-slate-400 font-mono bg-slate-900/60 px-3 py-1.5 rounded-lg border border-slate-800/60">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>{currentTime} UTC</span>
          </div>
        </div>
      </div>
    </header>
  );
};
