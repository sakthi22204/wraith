'use client';

import React, { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { toast } from 'sonner';
import { Finding } from '@/types/graph';
import { startRecon, fetchReconStatus, cancelRecon } from '@/lib/reconApi';
import { startAgentSession, fetchSessionStatus, stopAgentSession, fetchAgentSessions } from '@/lib/agentApi';
import { fetchFindings, fetchReviewQueue, deleteProgram as deleteInvestigation } from '@/lib/graphApi';
import { fetchReport } from '@/lib/reportingApi';
import SeverityBadge from '@/components/SeverityBadge';
import ActiveExploitApproval from '@/components/ActiveExploitApproval';

export default function InvestigationDashboard() {
  const { investigationId } = useParams();
  const router = useRouter();
  const [activeRecon, setActiveRecon] = useState<string | null>(null);
  const [isStartingRecon, setIsStartingRecon] = useState(false);
  const [activeAgent, setActiveAgent] = useState<string | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reviewCount, setReviewQueueCount] = useState(0);
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [isDeleting, setIsDeleteModalOpen] = useState(false);
  const [isReconModalOpen, setIsReconModalOpen] = useState(false);
  const [reconDomains, setReconDomains] = useState('');
  const [isCancelReconModalOpen, setIsCancelReconModalOpen] = useState(false);
  const [isStopAgentModalOpen, setIsStopAgentModalOpen] = useState(false);

  const loadData = async () => {
    try {
      const f = await fetchFindings(investigationId as string);
      setFindings(f);
      const r = await fetchReviewQueue(investigationId as string);
      setReviewQueueCount(r.length);

      // Load active agent session
      const sessions = await fetchAgentSessions(investigationId as string);
      const runningSession = sessions.find((s: any) => s.status === 'running');
      if (runningSession) {
          setActiveAgent(runningSession.id);
      } else {
          setActiveAgent(null);
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 10000);
    return () => clearInterval(interval);
  }, [investigationId]);

  const handleStartRecon = async () => {
    if (!reconDomains || isStartingRecon) return;
    setIsStartingRecon(true);
    try {
      const res = await startRecon(investigationId as string, reconDomains.split(',').map(s => s.trim()));
      setActiveRecon(res.session_id);
      setIsReconModalOpen(false);
      setReconDomains('');
      if (res.duplicate_of) {
          toast.info('Recon session already in progress for these domains');
      } else {
          toast.success('Recon session started');
      }
    } catch (e) {
      toast.error('Failed to start recon');
    } finally {
      setIsStartingRecon(false);
    }
  };

  const handleStartAgent = async () => {
    try {
      const res = await startAgentSession(investigationId as string, [], 10);
      setActiveAgent(res.session_id);
      toast.success('Agent session started');
      router.push(`/investigations/${investigationId}/agent/${res.session_id}`);
    } catch (e) {
      toast.error('Failed to start agent');
    }
  };

  const downloadReport = async (format: 'markdown' | 'pdf') => {
    try {
      const data = await fetchReport(investigationId as string, undefined, format);
      const blob = format === 'pdf' ? (data as Blob) : new Blob([data as string], { type: 'text/markdown' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `report_${investigationId}.${format === 'pdf' ? 'pdf' : 'md'}`;
      a.click();
    } catch (e) {
      toast.error('Failed to download report');
    }
  };

  const handleDelete = async () => {
    try {
      await deleteInvestigation(investigationId as string);
      toast.success('Investigation deleted');
      router.push('/');
    } catch (e) {
      toast.error('Failed to delete investigation');
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <Link href="/" className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block font-sans">← Back to Investigations</Link>
          <h1 className="text-4xl font-bold tracking-tight font-heading">Investigation Dashboard</h1>
          <p className="text-slate-400 font-mono text-xs mt-1">{investigationId}</p>
        </div>
        <div className="flex space-x-3 items-center">
           <Link href={`/investigations/${investigationId}/assessment`} className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all flex items-center active:scale-95 shadow-md">
             View Assessment
           </Link>
           <button onClick={() => downloadReport('markdown')} className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all border border-slate-700 active:scale-95">
             MD Report
           </button>
           <button onClick={() => downloadReport('pdf')} className="bg-slate-800 hover:bg-slate-700 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all border border-slate-700 active:scale-95">
             PDF Report
           </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
          <div className="flex items-center space-x-4 mb-4">
            <Link href={`/investigations/${investigationId}/recon-sessions`} className="bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center space-x-2">
               <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
               <span>Recon History</span>
            </Link>
            <Link href={`/investigations/${investigationId}/graph`} className="bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center space-x-2">
               <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 20l-5.447-2.724A2 2 0 013 15.487V6.513a2 2 0 011.553-1.943L9 2l5.447 2.724A2 2 0 0116 6.666v8.821a2 2 0 01-1.553 1.943L9 20z" /></svg>
               <span>Attack Surface Map</span>
            </Link>
            <Link href={`/investigations/${investigationId}/findings`} className="bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center space-x-2">
               <svg className="w-4 h-4 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
               <span>Findings List</span>
            </Link>
            <Link href={`/investigations/${investigationId}/agent`} className="bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center space-x-2">
               <svg className="w-4 h-4 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
               <span>Agent History</span>
            </Link>
          </div>

          <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-2xl overflow-hidden shadow-xl shadow-indigo-500/12">
            <div className="p-6 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
              <h2 className="font-bold text-lg flex items-center font-heading">
                <span className="w-2 h-2 bg-indigo-500 rounded-full mr-2"></span>
                Active Findings ({findings.length})
              </h2>
            </div>
            <div className="divide-y divide-slate-800">
              {findings.length === 0 ? (
                <div className="p-12 text-center text-slate-500 italic">No findings recorded yet. Start recon or an agent session.</div>
              ) : (
                findings.slice(0, 10).map((f: Finding) => (
                  <div key={f.id} className="p-4 flex items-center justify-between hover:bg-slate-800/30 transition-colors">
                    <div className="flex items-center space-x-4">
                      <SeverityBadge severity={f.severity} />
                      <div>
                        <div className="font-bold text-sm text-slate-200">{f.vuln_type.toUpperCase()}</div>
                        <div className="text-slate-400 text-xs truncate max-w-md">{f.description}</div>
                      </div>
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase bg-slate-950 px-2 py-1 rounded border border-slate-800">{f.status}</div>
                  </div>
                ))
              )}
            </div>
          </section>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
             <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-2xl p-6 space-y-4 hover:border-indigo-500/60 transition-all shadow-lg shadow-indigo-500/12">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-200 font-heading">Recon Cycle</h3>
                  <div className={`h-2 w-2 rounded-full ${activeRecon ? 'bg-indigo-500 animate-pulse' : 'bg-slate-700'}`}></div>
                </div>
                <p className="text-slate-400 text-sm">Orchestrate automated discovery across the investigation scope.</p>
                <div className="pt-2">
                  {activeRecon ? (
                    <div className="space-y-4">
                       <div className="bg-slate-950 rounded-xl p-4 flex justify-between items-center border border-slate-800">
                          <div className="flex flex-col">
                            <span className="text-[10px] font-bold text-slate-500 uppercase mb-1">Recon Active</span>
                            <span className="text-xs font-mono text-indigo-400 font-bold">Scanning...</span>
                          </div>
                          <button
                            onClick={() => setIsCancelReconModalOpen(true)}
                            className="bg-red-900/20 text-red-400 border border-red-900/50 px-3 py-1 rounded text-[10px] font-bold uppercase hover:bg-red-900/40 transition-colors"
                          >
                            Cancel
                          </button>
                       </div>
                    </div>
                  ) : (
                      <button onClick={() => setIsReconModalOpen(true)} className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-xl text-sm transition-all shadow-lg shadow-indigo-600/20 active:scale-95">
                      Start New Recon
                    </button>
                  )}
                </div>
             </section>

             <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 hover:border-indigo-500/30 transition-colors shadow-lg">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-200 font-heading">Exploit Agent</h3>
                  <div className={`h-2 w-2 rounded-full ${activeAgent ? 'bg-indigo-500 animate-pulse' : 'bg-slate-700'}`}></div>
                </div>
                <p className="text-slate-400 text-sm">Autonomous reasoning loop for live target validation.</p>
                <div className="pt-2">
                  {activeAgent ? (
                    <div className="space-y-3">
                       <Link href={`/investigations/${investigationId}/agent/${activeAgent}`} className="block text-center bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-bold py-3 rounded-xl text-sm hover:bg-indigo-600/30 transition-all active:scale-95">
                          Monitor Session
                       </Link>
                       <button
                        onClick={() => setIsStopAgentModalOpen(true)}
                        className="w-full text-red-500 text-[10px] font-bold uppercase hover:underline tracking-widest"
                       >
                         Stop Agent Boundary
                       </button>
                    </div>
                  ) : (
                    <button onClick={handleStartAgent} className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-xl text-sm transition-all shadow-lg shadow-indigo-600/20 active:scale-95">
                      Start Agent Session
                    </button>
                  )}
                </div>
             </section>
          </div>
        </div>

        <div className="space-y-8">
           <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-2xl p-6 overflow-hidden relative group shadow-lg shadow-indigo-500/12 hover:border-indigo-500/60 transition-all">
              <div className="absolute top-0 right-0 p-4 opacity-10 group-hover:opacity-20 transition-opacity">
                <svg className="w-16 h-16 text-indigo-500" fill="currentColor" viewBox="0 0 20 20"><path d="M9 2a1 1 0 000 2h2a1 1 0 100-2H9z" /><path fillRule="evenodd" d="M4 5a2 2 0 012-2 3 3 0 003 3h2a3 3 0 003-3 2 2 0 012 2v11a2 2 0 01-2 2H6a2 2 0 01-2-2V5zm3 4a1 1 0 000 2h.01a1 1 0 100-2H7zm3 0a1 1 0 000 2h3a1 1 0 100-2h-3zm-3 4a1 1 0 100 2h.01a1 1 0 100-2H7zm3 0a1 1 0 100 2h3a1 1 0 100-2h-3z" clipRule="evenodd" /></svg>
              </div>
              <h3 className="font-bold text-lg mb-2 text-slate-200 font-heading">Review Queue</h3>
              <p className="text-slate-400 text-sm mb-6">Validate low-confidence findings before they hit the final report.</p>
              <div className="flex items-baseline space-x-2 mb-6">
                <span className="text-5xl font-bold text-white tracking-tighter">{reviewCount}</span>
                <span className="text-slate-500 text-xs font-bold uppercase tracking-widest">Pending Verification</span>
              </div>
              <Link href={`/investigations/${investigationId}/review`} className="block w-full text-center bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-sm transition-all border border-slate-700 shadow-lg active:scale-95">
                Open Queue
              </Link>
           </section>

           <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-2xl p-6 shadow-lg shadow-indigo-500/12">
              <h3 className="font-bold text-lg mb-2 text-amber-500 flex items-center font-heading">
                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>
                Safety Gate
              </h3>
              <p className="text-slate-400 text-sm mb-4">Pending approvals for active exploitation modules.</p>
              <ActiveExploitApproval investigationId={investigationId as string} />
           </section>

           <div className="pt-10 border-t border-slate-800 mt-10">
              <h3 className="text-xs font-bold text-red-500 uppercase tracking-widest mb-4 flex items-center">
                 <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                 Danger Zone
              </h3>
              <button
                onClick={() => setIsDeleteModalOpen(true)}
                className="w-full bg-red-900/10 hover:bg-red-900/20 text-red-500 border border-red-900/30 font-bold py-3 rounded-xl text-sm transition-all"
              >
                Delete Investigation
              </button>
           </div>
        </div>
      </div>

      {isReconModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-xl font-bold font-heading">Start Recon Session</h3>
              <button onClick={() => setIsReconModalOpen(false)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Seed Domains (Comma-separated)</label>
                <textarea
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white outline-none focus:border-indigo-500 h-24"
                  value={reconDomains}
                  onChange={e => setReconDomains(e.target.value)}
                  placeholder="example.com, api.example.com"
                />
              </div>
              <button
                onClick={handleStartRecon}
                disabled={isStartingRecon}
                className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-xl transition-all shadow-lg shadow-indigo-600/20 active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isStartingRecon ? 'Starting...' : 'Start Recon'}
              </button>
            </div>
          </div>
        </div>
      )}

      {isCancelReconModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-xl font-bold text-red-500 font-heading">Cancel Recon</h3>
              <button onClick={() => setIsCancelReconModalOpen(false)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-slate-300">Are you sure you want to cancel the active recon session?</p>
              <div className="flex space-x-3">
                    <button onClick={() => setIsCancelReconModalOpen(false)} className="flex-1 bg-slate-800 text-white font-bold py-3 rounded-xl active:scale-95 transition-all">No, Keep Running</button>
                <button
                  onClick={() => {
                    if (!activeRecon) return;
                    cancelRecon(activeRecon).then(() => {
                      setActiveRecon(null);
                      setIsCancelReconModalOpen(false);
                      toast.success('Recon session cancelled');
                    });
                  }}
                  className="flex-1 bg-red-600 text-white font-bold py-3 rounded-xl active:scale-95 transition-all"
                >
                  Yes, Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isStopAgentModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-xl font-bold text-red-500 font-heading">Stop Agent</h3>
              <button onClick={() => setIsStopAgentModalOpen(false)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-slate-300">Are you sure you want to stop the agent session? This will halt all autonomous reasoning.</p>
              <div className="flex space-x-3">
                    <button onClick={() => setIsStopAgentModalOpen(false)} className="flex-1 bg-slate-800 text-white font-bold py-3 rounded-xl active:scale-95 transition-all">No, Keep Active</button>
                <button
                  onClick={() => {
                    if (!activeAgent) return;
                    stopAgentSession(activeAgent).then(() => {
                      setActiveAgent(null);
                      setIsStopAgentModalOpen(false);
                      toast.success('Agent session stopped');
                    });
                  }}
                  className="flex-1 bg-red-600 text-white font-bold py-3 rounded-xl active:scale-95 transition-all"
                >
                  Yes, Stop Agent
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {isDeleting && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-[100] p-4">
           <div className="bg-slate-900 border border-red-900/50 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
              <div className="p-6 bg-red-900/10 border-b border-red-900/30">
                 <h3 className="text-xl font-bold text-red-400 font-heading">Irreversible Action</h3>
              </div>
              <div className="p-6 space-y-4">
                 <p className="text-slate-400 text-sm">
                   This will delete the entire investigation knowledge graph including hosts, endpoints, findings, and audit history. This cannot be undone.
                 </p>
                 <div>
                    <label className="text-xs font-bold text-slate-500 uppercase block mb-2">Type investigation ID to confirm: <span className="text-slate-300 font-mono select-all">{investigationId}</span></label>
                    <input
                      className="w-full bg-slate-950 border border-red-900/30 rounded-xl p-3 text-white outline-none focus:border-red-500 font-mono text-sm"
                      value={deleteConfirm}
                      onChange={e => setDeleteConfirm(e.target.value)}
                      placeholder="Confirm ID"
                    />
                 </div>
                 <div className="flex space-x-3">
                    <button onClick={() => setIsDeleteModalOpen(false)} className="flex-1 bg-slate-800 text-white font-bold py-3 rounded-xl text-sm active:scale-95 transition-all">Cancel</button>
                    <button
                      onClick={handleDelete}
                      disabled={deleteConfirm !== investigationId}
                      className="flex-[2] bg-red-600 disabled:opacity-30 text-white font-bold py-3 rounded-xl text-sm shadow-lg shadow-red-900/20 active:scale-95 transition-all"
                    >
                      Delete Everything
                    </button>
                 </div>
              </div>
           </div>
        </div>
      )}
    </div>
  );
}
