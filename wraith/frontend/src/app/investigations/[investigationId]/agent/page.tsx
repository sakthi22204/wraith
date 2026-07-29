'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { fetchAgentSessions } from '@/lib/agentApi';
import Skeleton from '@/components/Skeleton';

export default function AgentSessionsPage() {
  const { investigationId } = useParams();
  const [sessions, setSessions] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    try {
      const data = await fetchAgentSessions(investigationId as string);
      setSessions(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [investigationId]);

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-8">
      <div>
        <Link href={`/investigations/${investigationId}`} className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block font-sans">← Back to Dashboard</Link>
        <h1 className="text-4xl font-bold tracking-tight">Agent Reasoning History</h1>
        <p className="text-slate-400 text-sm mt-1">Durable history of autonomous agent reasoning sessions for this investigation.</p>
      </div>

      <div className="space-y-4">
        {isLoading ? (
          [1, 2, 3].map(i => (
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
             No agent sessions recorded for this investigation.
          </div>
        ) : (
          sessions.map(session => (
            <div key={session.id} className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 border border-indigo-500/10 hover:border-indigo-500/30 rounded-2xl p-6 transition-all shadow-lg">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Session ID</span>
                  <div className="font-mono text-sm text-slate-200">{session.id}</div>
                </div>
                <span className={`text-xs font-bold uppercase tracking-widest px-3 py-1 rounded-full ${
                  session.status === 'completed' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' :
                  session.status === 'running' || session.status === 'accepted' ? 'bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 animate-pulse' :
                  'bg-red-500/10 text-red-400 border border-red-500/20'
                }`}>
                  {session.status}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-slate-800/50">
                 <div>
                    <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Iteration Count</label>
                    <div className="text-xs text-slate-300 font-mono">{session.iteration_count} / 10</div>
                 </div>
                 <div>
                    <label className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Started At</label>
                    <div className="text-xs text-slate-300">{new Date(session.started_at).toLocaleString()}</div>
                 </div>
                 <div className="flex items-end justify-end">
                      <Link href={`/investigations/${investigationId}/agent/${session.id}`} className="text-xs font-bold text-indigo-400 hover:underline">
                         View Reasoning Log →
                      </Link>
                 </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
