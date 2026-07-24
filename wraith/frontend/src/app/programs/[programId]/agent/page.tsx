'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { fetchAgentSessions } from '@/lib/agentApi';
import Skeleton from '@/components/Skeleton';

export default function AgentSessionsPage() {
  const { programId } = useParams();
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const loadSessions = async () => {
    try {
      const data = await fetchAgentSessions(programId as string);
      setSessions(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSessions();
    const interval = setInterval(loadSessions, 10000);
    return () => clearInterval(interval);
  }, [programId]);

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running':
        return 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30';
      case 'completed':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'stopped':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
      case 'paused_rate_limited':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30 animate-pulse';
      case 'failed':
        return 'bg-red-500/20 text-red-400 border-red-500/30';
      default:
        return 'bg-slate-500/20 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-8">
      <div>
        <Link href={`/programs/${programId}`} className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block">← Back to Dashboard</Link>
        <h1 className="text-4xl font-bold tracking-tight font-heading text-white">Agent Session History</h1>
        <p className="text-slate-400 text-sm mt-1">Durable history of autonomous agent reasoning sessions for this program.</p>
      </div>

      <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead className="bg-slate-900 border-b border-slate-800">
              <tr>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Session ID</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Status</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Iterations</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Outcome Report</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Started</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Completed</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    <td className="p-4"><Skeleton className="h-6 w-32 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-20 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-12 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-48 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-24 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-24 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-20 rounded-md" /></td>
                  </tr>
                ))
              ) : sessions.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-12 text-center text-slate-500 italic">No agent sessions found.</td>
                </tr>
              ) : (
                sessions.map((session) => (
                  <tr key={session.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="p-4 font-mono text-xs text-slate-300">
                      {session.id.slice(0, 8)}...
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-1 rounded text-[10px] font-black uppercase border ${getStatusColor(session.status)}`}>
                        {session.status}
                      </span>
                    </td>
                    <td className="p-4 text-xs text-slate-300 font-bold">
                      {session.iteration_count}
                    </td>
                    <td className="p-4 text-xs text-slate-400 truncate max-w-xs">
                      {session.final_report || 'Running or no final report yet'}
                    </td>
                    <td className="p-4 text-xs text-slate-400">
                      {new Date(session.started_at).toLocaleString()}
                    </td>
                    <td className="p-4 text-xs text-slate-400">
                      {session.completed_at ? new Date(session.completed_at).toLocaleString() : '-'}
                    </td>
                    <td className="p-4">
                      <Link href={`/programs/${programId}/agent/${session.id}`} className="text-xs font-bold text-indigo-400 hover:underline">
                        {session.status === 'running' ? 'Monitor' : 'View Detail'}
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
