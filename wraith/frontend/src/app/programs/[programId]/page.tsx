'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { startRecon, fetchReconStatus, cancelRecon } from '@/lib/reconApi';
import { startAgentSession, fetchSessionStatus, stopAgentSession } from '@/lib/agentApi';
import { fetchFindings, fetchReviewQueue } from '@/lib/graphApi';
import { fetchReport } from '@/lib/reportingApi';
import SeverityBadge from '@/components/SeverityBadge';
import ActiveExploitApproval from '@/components/ActiveExploitApproval';

export default function ProgramDashboard() {
  const { programId } = useParams();
  const [activeRecon, setActiveRecon] = useState<any>(null);
  const [activeAgent, setActiveAgent] = useState<any>(null);
  const [findings, setFindings] = useState<any[]>([]);
  const [reviewCount, setReviewQueueCount] = useState(0);

  const loadData = async () => {
    try {
      const f = await fetchFindings(programId as string);
      setFindings(f);
      const r = await fetchReviewQueue(programId as string);
      setReviewQueueCount(r.length);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [programId]);

  const handleStartRecon = async () => {
    try {
      const res = await startRecon(programId as string, []); // Using program defaults
      setActiveRecon(res.session_id);
    } catch (e) {
      alert('Failed to start recon');
    }
  };

  const handleStartAgent = async () => {
    try {
      const res = await startAgentSession(programId as string, [], 10);
      setActiveAgent(res.session_id);
    } catch (e) {
      alert('Failed to start agent');
    }
  };

  const downloadReport = async (format: 'markdown' | 'pdf') => {
    try {
      const data = await fetchReport(programId as string, undefined, format);
      const blob = format === 'pdf' ? (data as Blob) : new Blob([data as string], { type: 'text/markdown' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${programId}.${format === 'pdf' ? 'pdf' : 'md'}`;
      a.click();
    } catch (e) {
      alert('Failed to download report');
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <Link href="/" className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block">← Back to Programs</Link>
          <h1 className="text-4xl font-bold tracking-tight">Program Dashboard</h1>
          <p className="text-slate-400 font-mono text-xs mt-1">{programId}</p>
        </div>
        <div className="flex space-x-3">
           <button onClick={() => downloadReport('markdown')} className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm font-bold transition-colors border border-slate-700">
             MD Report
           </button>
           <button onClick={() => downloadReport('pdf')} className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm font-bold transition-colors border border-slate-700">
             PDF Report
           </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
          <section className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
            <div className="p-6 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
              <h2 className="font-bold text-lg">Active Findings ({findings.length})</h2>
              <Link href={`/programs/${programId}/graph`} className="text-indigo-400 text-sm font-bold hover:underline">Full Graph →</Link>
            </div>
            <div className="divide-y divide-slate-800">
              {findings.length === 0 ? (
                <div className="p-12 text-center text-slate-500 italic">No findings recorded yet.</div>
              ) : (
                findings.slice(0, 10).map((f: any) => (
                  <div key={f.id} className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition-colors">
                    <div className="flex items-center space-x-4">
                      <SeverityBadge severity={f.severity} />
                      <div>
                        <div className="font-bold text-sm">{f.vuln_type.toUpperCase()}</div>
                        <div className="text-slate-400 text-xs truncate max-w-md">{f.description}</div>
                      </div>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase">{f.status}</div>
                  </div>
                ))
              )}
            </div>
          </section>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
             <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold">Recon Cycle</h3>
                  <div className="h-2 w-2 rounded-full bg-slate-800 animate-pulse"></div>
                </div>
                <p className="text-slate-400 text-sm">Orchestrate automated discovery across the program scope.</p>
                <div className="pt-2">
                  {activeRecon ? (
                    <div className="space-y-4">
                       <div className="bg-slate-800 rounded-lg p-3 flex justify-between items-center">
                          <span className="text-xs font-mono text-indigo-400 animate-pulse uppercase font-bold">In Progress</span>
                          <button onClick={() => cancelRecon(activeRecon).then(() => setActiveRecon(null))} className="text-red-400 text-[10px] font-bold uppercase hover:underline">Cancel</button>
                       </div>
                    </div>
                  ) : (
                    <button onClick={handleStartRecon} className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded-lg text-sm transition-all shadow-lg shadow-indigo-600/20 active:scale-95">
                      Start New Recon
                    </button>
                  )}
                </div>
             </section>

             <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold">Exploit Agent</h3>
                  <div className="h-2 w-2 rounded-full bg-slate-800"></div>
                </div>
                <p className="text-slate-400 text-sm">Autonomous reasoning loop for vulnerability validation.</p>
                <div className="pt-2">
                  {activeAgent ? (
                    <div className="space-y-3">
                       <Link href={`/programs/${programId}/agent/${activeAgent}`} className="block text-center bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-bold py-2 rounded-lg text-sm hover:bg-indigo-600/30 transition-colors">
                          Monitor Session
                       </Link>
                       <button onClick={() => stopAgentSession(activeAgent).then(() => setActiveAgent(null))} className="w-full text-red-400 text-[10px] font-bold uppercase hover:underline">Stop Agent</button>
                    </div>
                  ) : (
                    <button onClick={handleStartAgent} className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded-lg text-sm transition-all shadow-lg shadow-indigo-600/20 active:scale-95">
                      Start Agent Session
                    </button>
                  )}
                </div>
             </section>
          </div>
        </div>

        <div className="space-y-8">
           <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 overflow-hidden relative group">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <svg className="w-16 h-16" fill="currentColor" viewBox="0 0 20 20"><path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" /><path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" /></svg>
              </div>
              <h3 className="font-bold text-lg mb-2">Review Queue</h3>
              <p className="text-slate-400 text-sm mb-6">Validate low-confidence findings before they hit the final report.</p>
              <div className="flex items-baseline space-x-2 mb-6">
                <span className="text-4xl font-bold text-white">{reviewCount}</span>
                <span className="text-slate-500 text-sm font-medium uppercase tracking-wider">Pending</span>
              </div>
              <Link href={`/programs/${programId}/review`} className="block w-full text-center bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-sm transition-colors border border-slate-700">
                Open Queue
              </Link>
           </section>

           <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
              <h3 className="font-bold text-lg mb-2 text-amber-500 flex items-center">
                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>
                Safety Gate
              </h3>
              <p className="text-slate-400 text-sm mb-4">Pending approvals for active exploitation modules.</p>
              <ActiveExploitApproval programId={programId as string} />
           </section>
        </div>
      </div>
    </div>
  );
}
