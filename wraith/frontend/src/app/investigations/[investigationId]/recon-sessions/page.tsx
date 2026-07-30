'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { listReconSessions, fetchReconStatus, ReconSession } from '@/lib/reconApi';
import Skeleton from '@/components/Skeleton';

export default function ReconSessionsPage() {
  const { investigationId } = useParams();
  const [sessions, setSessions] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    try {
      const data = await listReconSessions(investigationId as string);

      const updatedSessions = await Promise.all(
        data.map(async (s) => {
          if (s.status === 'running' || s.status === 'accepted') {
            try {
              const liveStatus = await fetchReconStatus(s.id);
              return { ...s, ...liveStatus };
            } catch (e) {
              console.error(`Failed to fetch live status for session ${s.id}:`, e);
            }
          }
          return s;
        })
      );

      setSessions(updatedSessions);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();

    const hasActive = sessions.some(s => s.status === 'running' || s.status === 'accepted');
    const intervalTime = hasActive ? 3000 : 10000;

    const interval = setInterval(loadData, intervalTime);
    return () => clearInterval(interval);
  }, [investigationId, sessions.map(s => s.status).join(',')]);

  const getToolStatusColor = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed': return 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
      case 'running': return 'bg-sky-500/15 text-sky-400 border border-sky-500/30 animate-pulse';
      case 'retrying': return 'bg-amber-500/15 text-amber-400 border border-amber-500/30 animate-pulse';
      case 'failed': return 'bg-red-500/10 text-red-400 border border-red-500/20';
      case 'waiting': default: return 'bg-slate-800 text-slate-400 border border-slate-700/50';
    }
  };

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
      <div>
        <Link href={`/investigations/${investigationId}`} className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block font-sans">← Back to Dashboard</Link>
        <h1 className="text-4xl font-bold tracking-tight">Recon History & Live Execution</h1>
        <p className="text-slate-400 text-sm mt-1">Live execution timeline, tool logs, and status tracking for this investigation.</p>
      </div>

      <div className="space-y-8">
        {isLoading && sessions.length === 0 ? (
          [1, 2].map(i => (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-3">
              <div className="flex justify-between">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 w-16" />
              </div>
              <Skeleton className="h-4 w-1/2" />
            </div>
          ))
        ) : sessions.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center text-slate-500 italic">
             No recon sessions recorded for this investigation.
          </div>
        ) : (
          sessions.map(session => {
            const toolStatuses = session.tool_statuses || {};
            const logs = session.logs || [];

            // Extract unique tool names from toolStatuses keys dynamically
            const toolNames = Array.from(new Set(Object.keys(toolStatuses).map(k => k.split(":")[0])));
            const sortedToolNames = toolNames.length > 0 ? toolNames.sort() : [
              'subfinder', 'naabu', 'httpx_probe', 'katana', 'dnsx', 'tlsx', 'gau', 'waybackurls',
              'ffuf', 'kiterunner', 'linkfinder', 'secretfinder', 'trufflehog', 'gittools', 'wpscan', 'cloud_enum'
            ];

            return (
              <div key={session.id} className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 border border-indigo-500/15 hover:border-indigo-500/25 rounded-2xl p-6 transition-all shadow-xl space-y-6">

                {/* Session Header */}
                <div className="flex flex-col md:flex-row md:justify-between md:items-center gap-4 pb-4 border-b border-slate-800/50">
                  <div>
                    <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Session ID</span>
                    <div className="font-mono text-sm text-slate-200">{session.id}</div>
                  </div>
                  <div className="flex items-center space-x-3">
                    {session.current_tool && (
                      <div className="flex items-center space-x-2 bg-indigo-950/30 text-indigo-400 px-3 py-1 rounded-full text-xs font-semibold border border-indigo-500/20">
                        <span className="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-ping"></span>
                        <span>Running: {session.current_tool}</span>
                      </div>
                    )}
                    <span className={`text-xs font-bold uppercase tracking-widest px-3 py-1 rounded-full ${
                      session.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                      session.status === 'running' || session.status === 'accepted' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 animate-pulse' :
                      'bg-red-500/10 text-red-400 border border-red-500/20'
                    }`}>
                      {session.status}
                    </span>
                  </div>
                </div>

                {/* Progress Bar */}
                <div className="space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-400 font-medium">Execution Progress</span>
                    <span className="font-mono font-bold text-white">{Math.round(session.progress || 0)}%</span>
                  </div>
                  <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
                    <div
                      className="bg-indigo-600 h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(99,102,241,0.4)]"
                      style={{ width: `${session.progress || 0}%` }}
                    />
                  </div>
                </div>

                {/* Grid Timeline of Tools (Dynamically Rendered!) */}
                <div className="space-y-3">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Execution Timeline</h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {sortedToolNames.map(toolName => {
                      const matchingKeys = Object.keys(toolStatuses).filter(k => k.startsWith(`${toolName}:`));
                      const toolStatus = matchingKeys.length > 0 ? toolStatuses[matchingKeys[0]] : 'waiting';

                      return (
                        <div key={toolName} className="bg-slate-950/40 p-4 rounded-xl border border-slate-800 flex flex-col items-center justify-between text-center space-y-2 hover:border-slate-700/50 transition-colors">
                          <span className="text-xs font-bold text-slate-300 capitalize">{toolName}</span>
                          <span className={`text-[10px] font-black uppercase tracking-wider px-2 py-0.5 rounded ${getToolStatusColor(toolStatus)}`}>
                            {toolStatus}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Execution Terminal / Logs */}
                {logs.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">Live Execution Logs</h3>
                    <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 h-48 overflow-y-auto font-mono text-[11px] text-indigo-300/90 leading-relaxed shadow-inner flex flex-col space-y-1 scroll-smooth">
                      {logs.map((log: string, index: number) => (
                        <div key={index} className="hover:bg-slate-900/30 px-1 py-0.5 rounded transition-colors whitespace-pre-wrap">
                          <span className="text-indigo-500/60 font-bold select-none mr-2">›</span>
                          {log}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Session Footer Info */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-slate-800/50 text-xs">
                   <div>
                      <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Seed Target</label>
                      <div className="text-slate-300 font-mono truncate">{session.domains.join(', ')}</div>
                   </div>
                   <div>
                      <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Started At</label>
                      <div className="text-slate-300">{new Date(session.started_at).toLocaleString()}</div>
                   </div>
                   {session.tool_results && (
                     <div>
                        <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Findings Summary</label>
                        <div className="space-x-3 text-slate-400">
                           <span>Hosts: <strong className="text-white font-bold">{session.tool_results.hosts_found}</strong></span>
                           <span>Ports: <strong className="text-white font-bold">{session.tool_results.ports_found}</strong></span>
                           <span>Endpoints: <strong className="text-white font-bold">{session.tool_results.endpoints_found}</strong></span>
                        </div>
                     </div>
                   )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
