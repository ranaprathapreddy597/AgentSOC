import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, Copy, Check, Code, Tag, Radio } from 'lucide-react';
import type { IngestResponse } from '../types/soc';

interface TelemetryStreamProps {
  currentResponse: IngestResponse | null;
}

export const TelemetryStream: React.FC<TelemetryStreamProps> = ({ currentResponse }) => {
  const [copied, setCopied] = useState<boolean>(false);

  if (!currentResponse) {
    return (
      <div className="cyber-glass-card rounded-2xl p-8 border border-slate-800/80 shadow-2xl flex flex-col items-center justify-center text-center min-h-[320px]">
        <Radio className="w-12 h-12 text-slate-700 animate-pulse mb-3" />
        <h3 className="text-sm font-semibold text-slate-400">Awaiting Telemetry Stream...</h3>
        <p className="text-xs text-slate-600 max-w-sm mt-1">
          Submit a telemetry log or select an adversarial test vector from the left console to trigger real-time pipeline mitigation.
        </p>
      </div>
    );
  }

  const enriched = currentResponse.enriched_incident_object;
  const isQuarantined = currentResponse.quarantined || currentResponse.status === 'rejected';

  const handleCopyId = () => {
    if (enriched?.incident_id) {
      navigator.clipboard.writeText(enriched.incident_id);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const getFlagBadge = (flag: string) => {
    switch (flag) {
      case 'PII_REDACTED':
        return 'bg-purple-500/10 text-purple-300 border-purple-500/30';
      case 'SLM_PROMPT_INJECTION_DETECTED':
        return 'bg-rose-500/10 text-rose-300 border-rose-500/30 glow-rose';
      case 'CONTEXT_STITCHING_DETECTED':
        return 'bg-amber-500/10 text-amber-300 border-amber-500/30';
      case 'SLM_CHECK_PASSED':
        return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
      default:
        return 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30';
    }
  };

  return (
    <div className={`cyber-glass-card rounded-2xl p-5 border shadow-2xl space-y-4 transition-all duration-300 ${
      isQuarantined ? 'border-rose-500/40 glow-rose' : 'border-slate-800/80'
    }`}>
      {/* Incident Header & Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex items-center space-x-2.5">
          {isQuarantined ? (
            <ShieldAlert className="w-5 h-5 text-rose-400 animate-pulse" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          )}
          <div>
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                Enriched Incident Telemetry
              </h2>
              <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                isQuarantined ? 'bg-rose-500/20 text-rose-300 border border-rose-500/50' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
              }`}>
                {isQuarantined ? 'QUARANTINED THREAT' : 'VERIFIED INGESTION'}
              </span>
            </div>
            {enriched && (
              <div className="flex items-center space-x-2 text-[11px] font-mono text-slate-400 mt-0.5">
                <span>ID: {enriched.incident_id.slice(0, 18)}...</span>
                <button
                  type="button"
                  onClick={handleCopyId}
                  className="hover:text-cyan-400 transition-colors"
                  title="Copy Incident ID"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="text-right font-mono text-xs text-slate-400">
          <div>{enriched?.timestamp ? new Date(enriched.timestamp).toLocaleTimeString() : ''}</div>
          <div className="text-[10px] text-slate-500">Latency: {currentResponse.pipeline_latency_ms.toFixed(1)}ms</div>
        </div>
      </div>

      {/* Structural Context Details */}
      {enriched?.structural_context && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 bg-slate-950/60 rounded-xl p-3 border border-slate-800/80 font-mono text-xs">
          <div>
            <span className="text-[10px] text-slate-500 block">SOURCE IP</span>
            <span className="text-cyan-300 font-semibold">{enriched.structural_context.source_ip}</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 block">TARGET ASSET</span>
            <span className="text-indigo-300 font-semibold">{enriched.structural_context.target_ip}</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 block">CRITICALITY</span>
            <span className="text-amber-400 font-semibold">{enriched.structural_context.criticality}</span>
          </div>
          <div>
            <span className="text-[10px] text-slate-500 block">ZONE</span>
            <span className="text-slate-300">{enriched.structural_context.zone}</span>
          </div>
        </div>
      )}

      {/* Security Flags */}
      {enriched?.security_flags && enriched.security_flags.length > 0 && (
        <div className="space-y-1.5">
          <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
            <Tag className="w-3.5 h-3.5 text-cyan-400" />
            <span>Active Security Flags:</span>
          </span>
          <div className="flex flex-wrap gap-2">
            {enriched.security_flags.map((flag, idx) => (
              <span
                key={idx}
                className={`text-[11px] font-mono px-2.5 py-0.5 rounded-md border ${getFlagBadge(flag)}`}
              >
                {flag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Sanitized Encapsulated Payload Box */}
      <div className="space-y-1.5">
        <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
          <Code className="w-3.5 h-3.5 text-cyan-400" />
          <span>Sanitized XML-Encapsulated Payload:</span>
        </span>
        <div className="bg-slate-950/95 border border-slate-800 rounded-xl p-3 font-mono text-xs text-cyan-300 overflow-x-auto shadow-inner">
          <pre className="whitespace-pre-wrap break-all leading-relaxed">
            {currentResponse.processed_payload || enriched?.sanitized_payload}
          </pre>
        </div>
      </div>

      {/* Active Closed-Loop Docker Sandbox Isolation Confirmation */}
      {currentResponse.sandbox_confirmation && (
        <div className="mt-4 border border-rose-500/30 bg-rose-950/20 rounded-xl p-4 shadow-[0_0_15px_rgba(244,63,94,0.15)]">
          <span className="text-[11px] font-mono font-bold text-rose-400 flex items-center space-x-2 mb-2 uppercase tracking-wide">
            <ShieldAlert className="w-4 h-4" />
            <span>Autonomous Container Isolation Executed</span>
          </span>
          <div className="grid grid-cols-2 gap-3 font-mono text-[10px]">
            <div>
              <span className="text-slate-500 block mb-0.5">CONTAINER ID</span>
              <span className="text-slate-300 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                {currentResponse.sandbox_confirmation.container_id}
              </span>
            </div>
            <div>
              <span className="text-slate-500 block mb-0.5">TARGET IP NETWORK</span>
              <span className="text-rose-300 font-bold bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                SEVERED: {currentResponse.sandbox_confirmation.target_ip}
              </span>
            </div>
            <div className="col-span-2">
              <span className="text-slate-500 block mb-0.5">ISOLATION TIMESTAMP (UTC)</span>
              <span className="text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 inline-block">
                {currentResponse.sandbox_confirmation.timestamp}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
