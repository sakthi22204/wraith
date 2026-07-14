'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { listReconSessions, ReconSession } from '@/lib/reconApi';
import Skeleton from '@/components/Skeleton';

export default function ReconSessionsPage() {
  const { programId } = useParams();
  const [sessions, setSessions] = useState<ReconSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedSession, setExpandedSession] = useState<string | null>(null);

  const loadSessions = async () => {
    try {
      const data = await listReconSessions(programId as string);
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
      case 'accepted':
        return 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30';
      case 'completed':
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
      case 'partial':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
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
        <h1 className="text-4xl font-bold tracking-tight font-heading text-white">Recon Session History</h1>
        <p className="text-slate-400 text-sm mt-1">Durable history of discovery activities for this program.</p>
      </div>

      <div className="bg-slate-900/50 backdrop-blur-md border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead className="bg-slate-900 border-b border-slate-800">
              <tr>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Status</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Domains Scanned</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Results Summary</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Started</th>
                <th className="p-4 text-xs font-black uppercase tracking-widest text-slate-500">Completed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    <td className="p-4"><Skeleton className="h-6 w-20 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-40 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-32 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-24 rounded-md" /></td>
                    <td className="p-4"><Skeleton className="h-6 w-24 rounded-md" /></td>
                  </tr>
                ))
              ) : sessions.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-12 text-center text-slate-500 italic">No recon sessions found.</td>
                </tr>
              ) : (
                sessions.map((session) => (
                  <React.Fragment key={session.id}>
                    <tr
                      className="hover:bg-slate-800/30 transition-colors cursor-pointer group"
                      onClick={() => setExpandedSession(expandedSession === session.id ? null : session.id)}
                    >
                      <td className="p-4">
                        <span className={`px-2 py-1 rounded text-[10px] font-black uppercase border ${getStatusColor(session.status)}`}>
                          {session.status}
                        </span>
                      </td>
                      <td className="p-4 font-mono text-xs text-slate-300">
                        {session.domains.join(', ')}
                      </td>
                      <td className="p-4">
                        <div className="flex space-x-3 text-[10px] font-bold">
                          <span className="text-blue-400">H: {session.tool_results?.hosts_found ?? 0}</span>
                          <span className="text-purple-400">P: {session.tool_results?.ports_found ?? 0}</span>
                          <span className="text-emerald-400">E: {session.tool_results?.endpoints_found ?? 0}</span>
                        </div>
                      </td>
                      <td className="p-4 text-xs text-slate-400">
                        {new Date(session.started_at).toLocaleString()}
                      </td>
                      <td className="p-4 text-xs text-slate-400">
                        {session.completed_at ? new Date(session.completed_at).toLocaleString() : '-'}
                      </td>
                    </tr>
                    {expandedSession === session.id && (
                      <tr className="bg-slate-950/50">
                        <td colSpan={5} className="p-6 border-l-2 border-l-indigo-500">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                            {session.tool_results?.tool_statuses && Object.entries(session.tool_results.tool_statuses).map(([tool, status]) => (
                              <div key={tool} className="bg-slate-900 border border-slate-800 p-3 rounded-xl flex items-center justify-between">
                                <span className="text-xs font-bold text-slate-400">{tool}</span>
                                <span className={`text-[10px] font-black uppercase ${status === 'completed' ? 'text-emerald-400' : status === 'running' ? 'text-indigo-400 animate-pulse' : 'text-red-400'}`}>
                                  {status}
                                </span>
                              </div>
                            ))}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
