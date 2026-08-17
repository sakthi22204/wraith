'use client';

import React, { useState, useEffect, useRef } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { toast } from 'sonner';
import { Finding, GraphResponse } from '@/types/graph';
import { startRecon, fetchReconStatus, cancelRecon, listReconSessions } from '@/lib/reconApi';
import { startAgentSession, fetchSessionStatus, stopAgentSession, fetchAgentSessions } from '@/lib/agentApi';
import { fetchFindings, fetchReviewQueue, deleteProgram as deleteInvestigation, fetchGraph } from '@/lib/graphApi';
import { fetchReport } from '@/lib/reportingApi';
import SeverityBadge from '@/components/SeverityBadge';
import ActiveExploitApproval from '@/components/ActiveExploitApproval';
import ScopeRules from '@/components/ScopeRules';
import { config } from '@/lib/config';

export default function InvestigationDashboard() {
  const { investigationId } = useParams();
  const router = useRouter();

  const [notFound, setNotFound] = useState(false);

  // Graph and Stats States
  const [graphStats, setGraphStats] = useState({
    hosts: 0,
    services: 0,
    endpoints: 0,
    findings: 0
  });

  // Findings & Queue
  const [findings, setFindings] = useState<Finding[]>([]);
  const [reviewCount, setReviewQueueCount] = useState(0);

  // Assessment & Approvals States
  const [riskScore, setRiskScore] = useState<number | null>(null);

  // Recon Session Real-time States
  const [activeReconId, setActiveReconId] = useState<string | null>(null);
  const [reconProgress, setReconProgress] = useState(0);
  const [reconCurrentTool, setReconCurrentTool] = useState<string | null>(null);
  const [reconCompletedTools, setReconCompletedTools] = useState<string[]>([]);
  const [reconFailedTools, setReconFailedTools] = useState<string[]>([]);
  const [reconLogs, setReconLogs] = useState<string[]>([]);
  const [reconStartTime, setReconStartTime] = useState<string | null>(null);

  // Agent Session Real-time States
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null);
  const [agentStartTime, setAgentStartTime] = useState<string | null>(null);
  const [agentLogs, setAgentLogs] = useState<string[]>([]);
  const [agentCurrentTool, setAgentCurrentTool] = useState<string | null>(null);

  // Live Timer State (MM:SS formatting)
  const [reconElapsed, setReconElapsed] = useState('00:00');
  const [agentElapsed, setAgentElapsed] = useState('00:00');

  // Modal / UI States
  const [isStartingRecon, setIsStartingRecon] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState('');
  const [isDeleting, setIsDeleteModalOpen] = useState(false);
  const [isReconModalOpen, setIsReconModalOpen] = useState(false);
  const [reconDomains, setReconDomains] = useState('');
  const [isCancelReconModalOpen, setIsCancelReconModalOpen] = useState(false);
  const [isStopAgentModalOpen, setIsStopAgentModalOpen] = useState(false);

  // Terminal scroll helper ref
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Helper to format duration from ISO timestamp to now
  const computeDurationString = (startedAt: string | null): string => {
    if (!startedAt) return '00:00';
    const start = new Date(startedAt).getTime();
    const now = Date.now();
    const diff = Math.max(0, now - start);
    const secs = Math.floor(diff / 1000);
    const minutes = Math.floor(secs / 60);
    const hours = Math.floor(minutes / 60);

    const formattedSecs = String(secs % 60).padStart(2, '0');
    const formattedMins = String(minutes % 60).padStart(2, '0');

    if (hours > 0) {
      return `${String(hours).padStart(2, '0')}:${formattedMins}:${formattedSecs}`;
    }
    return `${formattedMins}:${formattedSecs}`;
  };

  // Poll timer loop for active sessions (updates every 1s)
  useEffect(() => {
    const timer = setInterval(() => {
      if (reconStartTime) {
        setReconElapsed(computeDurationString(reconStartTime));
      } else {
        setReconElapsed('00:00');
      }
      if (agentStartTime) {
        setAgentElapsed(computeDurationString(agentStartTime));
      } else {
        setAgentElapsed('00:00');
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [reconStartTime, agentStartTime]);

  // Terminal scroll to bottom on new logs
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [reconLogs, agentLogs]);

  // Real-time Automated Polling Handler (runs every 2s)
  const loadData = async () => {
    try {
      const investigation_id = investigationId as string;

      // 0. Check if investigation exists (once, on first load)
      if (!notFound) {
        try {
          const checkResp = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigation_id}`);
          if (checkResp.status === 404) {
            setNotFound(true);
            return;
          }
        } catch {
          // Network error — keep polling, don't set notFound
        }
      } else {
        return;
      }

      // 1. Fetch Graph & compute stats dynamically
      try {
        const graphData: GraphResponse = await fetchGraph(investigation_id);
        const nodes = graphData.nodes || [];
        const counts = { hosts: 0, services: 0, endpoints: 0, findings: 0 };
        nodes.forEach(n => {
          if (n.labels.includes('Host')) counts.hosts++;
          if (n.labels.includes('Service')) counts.services++;
          if (n.labels.includes('Endpoint')) counts.endpoints++;
          if (n.labels.includes('Finding')) counts.findings++;
        });
        setGraphStats(counts);
      } catch (e) {
        console.error('Failed to poll graph statistics', e);
      }

      // 2. Fetch Findings & Review Queue length
      try {
        const f = await fetchFindings(investigation_id);
        setFindings(f);
        const r = await fetchReviewQueue(investigation_id);
        setReviewQueueCount(r.length);
      } catch (e) {
        console.error('Failed to poll findings or review queue', e);
      }

      // 3. Fetch Assessment risk score
      try {
        const assessResp = await fetch(`${config.assessmentUrl}/api/v1/assessments/${investigation_id}`);
        if (assessResp.ok) {
          const assessData = await assessResp.json();
          setRiskScore(assessData.risk_score);
        }
      } catch (e) {
        console.error('Failed to poll assessment score', e);
      }

      // 4. Poll active Recon Session details
      try {
        const sessions = await listReconSessions(investigation_id);
        const activeRecon = sessions.find(s => s.status === 'running' || s.status === 'accepted');
        if (activeRecon) {
          setActiveReconId(activeRecon.id);
          setReconStartTime(activeRecon.started_at);

          // Fetch live recon status metrics (progress, logs, current_tool, tool_statuses)
          const status = await fetchReconStatus(activeRecon.id);
          setReconProgress(status.progress || 0);
          setReconCurrentTool(status.current_tool || null);
          setReconLogs(status.logs || []);

          // Separate completed and failed tools
          const toolStatuses = status.tool_statuses || {};
          const completed: string[] = [];
          const failed: string[] = [];
          Object.entries(toolStatuses).forEach(([tool, state]) => {
            if (state === 'completed') completed.push(tool);
            if (state === 'failed') failed.push(tool);
          });
          setReconCompletedTools(completed);
          setReconFailedTools(failed);
        } else {
          setActiveReconId(null);
          setReconStartTime(null);
          setReconProgress(0);
          setReconCurrentTool(null);
        }
      } catch (e) {
        console.error('Failed to poll recon sessions', e);
      }

      // 6. Poll active Agent Session details
      try {
        const agentSessions = await fetchAgentSessions(investigation_id);
        const activeAgent = agentSessions.find((s: any) => s.status === 'running');
        if (activeAgent) {
          setActiveAgentId(activeAgent.id);
          setAgentStartTime(activeAgent.started_at);

          // Fetch live status for agent
          const agentStatus = await fetchSessionStatus(activeAgent.id);
          setAgentLogs(agentStatus.reasoning_log || []);
          if (agentStatus.tools_used && agentStatus.tools_used.length > 0) {
            setAgentCurrentTool(agentStatus.tools_used[agentStatus.tools_used.length - 1]);
          } else {
            setAgentCurrentTool(null);
          }
        } else {
          setActiveAgentId(null);
          setAgentStartTime(null);
          setAgentCurrentTool(null);
        }
      } catch (e) {
        console.error('Failed to poll agent sessions', e);
      }
    } catch (e) {
      console.error('Dashboard polling cycle error', e);
    }
  };

  // Polling Trigger (polls every 2 seconds without full page refreshes)
  useEffect(() => {
    loadData();
    const pollingInterval = setInterval(loadData, 2000);
    return () => clearInterval(pollingInterval);
  }, [investigationId]);

  const handleStartRecon = async () => {
    if (!reconDomains || isStartingRecon) return;
    setIsStartingRecon(true);
    try {
      const res = await startRecon(investigationId as string, reconDomains.split(',').map(s => s.trim()));
      setActiveReconId(res.session_id);
      setIsReconModalOpen(false);
      setReconDomains('');
      if (res.duplicate_of) {
          toast.info('Recon session already in progress for these domains');
      } else {
          toast.success('Recon session started');
      }
      loadData();
    } catch (e) {
      toast.error('Failed to start recon');
    } finally {
      setIsStartingRecon(false);
    }
  };

  const handleStartAgent = async () => {
    try {
      const res = await startAgentSession(investigationId as string, [], 10);
      setActiveAgentId(res.session_id);
      toast.success('Agent session started');
      router.push(`/investigations/${investigationId}/agent/${res.session_id}`);
    } catch (e) {
      toast.error('Failed to start agent');
    }
  };

  const downloadReport = async (format: 'markdown' | 'pdf' | 'html' | 'json') => {
    try {
      const data = await fetchReport(investigationId as string, undefined, format);
      let blob;
      if (format === 'pdf') {
        blob = data as Blob;
      } else if (format === 'html') {
        blob = new Blob([data as string], { type: 'text/html' });
      } else if (format === 'json') {
        blob = new Blob([data as string], { type: 'application/json' });
      } else {
        blob = new Blob([data as string], { type: 'text/markdown' });
      }
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'markdown' ? 'md' : format;
      a.download = `report_${investigationId}.${ext}`;
      a.click();
    } catch (e) {
      toast.error('Failed to download report');
    }
  };

  const handleDelete = async () => {
    try {
      const result = await deleteInvestigation(investigationId as string);
      if (result?.warning) {
        toast.warning(`Investigation deleted, but: ${result.warning}`);
      } else {
        toast.success('Investigation deleted');
      }
      router.push('/');
    } catch (e) {
      toast.error('Failed to delete investigation');
    }
  };

  // Severity Chart calculations
  const severityCounts = {
    critical: findings.filter(f => f.severity.toLowerCase() === 'critical').length,
    high: findings.filter(f => f.severity.toLowerCase() === 'high').length,
    medium: findings.filter(f => f.severity.toLowerCase() === 'medium').length,
    low: findings.filter(f => f.severity.toLowerCase() === 'low').length,
    info: findings.filter(f => f.severity.toLowerCase() === 'info').length
  };
  const totalSeverities = findings.length || 1;

  // Determine Current Phase dynamically
  const getCurrentPhase = (): string => {
    if (activeReconId) return 'Recon';
    if (activeAgentId) return 'Exploit Validation';
    if (findings.length > 0) return 'Reporting';
    return 'Pending';
  };

  if (notFound) {
    return (
      <div className="space-y-8 font-sans">
        <div>
          <Link href="/" className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block">← Back to Investigations</Link>
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-12 text-center mt-8">
            <h2 className="text-2xl font-bold text-slate-300 mb-2">Investigation Not Found</h2>
            <p className="text-slate-500 text-sm mb-6">No investigation exists with ID <span className="font-mono text-slate-400">{investigationId as string}</span>.</p>
            <Link href="/" className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all inline-block">
              Back to Investigations
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 font-sans">
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <Link href="/" className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block font-sans">← Back to Investigations</Link>
          <h1 className="text-4xl font-bold tracking-tight font-heading flex items-center gap-3">
            Investigation Dashboard
            <span className="text-xs bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 px-2.5 py-1 rounded-full uppercase font-mono font-bold tracking-widest">
              {getCurrentPhase()} Phase
            </span>
          </h1>
          <p className="text-slate-400 font-mono text-xs mt-1">{investigationId}</p>
        </div>
        <div className="flex flex-wrap gap-2 items-center">
           <Link href={`/investigations/${investigationId}/assessment`} className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-bold transition-all flex items-center active:scale-95 shadow-md">
             View Assessment
           </Link>
           <button onClick={() => downloadReport('markdown')} className="bg-slate-800 hover:bg-slate-700 text-white px-3 py-2 rounded-lg text-sm font-bold transition-all border border-slate-700 active:scale-95 shadow-md">
             MD Report
           </button>
           <button onClick={() => downloadReport('pdf')} className="bg-slate-800 hover:bg-slate-700 text-white px-3 py-2 rounded-lg text-sm font-bold transition-all border border-slate-700 active:scale-95 shadow-md">
             PDF Report
           </button>
           <button onClick={() => downloadReport('html')} className="bg-slate-800 hover:bg-slate-700 text-white px-3 py-2 rounded-lg text-sm font-bold transition-all border border-slate-700 active:scale-95 shadow-md">
             HTML Report
           </button>
           <button onClick={() => downloadReport('json')} className="bg-slate-800 hover:bg-slate-700 text-white px-3 py-2 rounded-lg text-sm font-bold transition-all border border-slate-700 active:scale-95 shadow-md">
             JSON Report
           </button>
        </div>
      </div>

      {/* Real-time Status and Phase Indicator Bar */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
         <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Dashboard Phase</span>
            <div className="text-lg font-bold text-slate-200">{getCurrentPhase()}</div>
         </div>
         <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Assessment Risk Rating</span>
            <div className="text-lg font-bold text-rose-500">{riskScore ? `${riskScore.toFixed(1)} / 10` : 'N/A'}</div>
         </div>
         <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Exploitation Status</span>
            <div className="text-lg font-bold text-emerald-400">
               ✓ Active
            </div>
         </div>
         <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5 space-y-1">
            <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Report Generation Status</span>
            <div className="text-lg font-bold text-indigo-400">{findings.length > 0 ? 'Ready to Export' : 'No findings'}</div>
         </div>
      </div>

      {/* Real-time Active Operation Panels */}
      {(activeReconId || activeAgentId) && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 bg-slate-950 border border-indigo-500/20 rounded-3xl p-6 shadow-2xl">
          {/* Active Recon Stats Panel */}
          {activeReconId ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-indigo-500"></span>
                  </span>
                  <span className="text-xs font-bold text-slate-300 font-mono">RECON PIPELINE ACTIVE</span>
                </div>
                <div className="text-xs text-slate-500 font-mono">Running time: <span className="text-indigo-400 font-bold">{reconElapsed}</span></div>
              </div>

              <div className="grid grid-cols-3 gap-4 bg-slate-900/50 p-4 rounded-xl border border-slate-800 text-center">
                <div>
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Current Tool</div>
                  <div className="text-xs font-bold text-indigo-400 mt-1 font-mono truncate">{reconCurrentTool || 'Waiting...'}</div>
                </div>
                <div>
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Completed Tools</div>
                  <div className="text-xs font-bold text-slate-300 mt-1">{reconCompletedTools.length}</div>
                </div>
                <div>
                  <div className="text-[10px] font-bold text-slate-500 uppercase">Failed Tools</div>
                  <div className="text-xs font-bold text-red-400 mt-1">{reconFailedTools.length}</div>
                </div>
              </div>

              <div className="space-y-1.5">
                <div className="flex justify-between text-[10px] font-bold text-slate-400 uppercase">
                  <span>Pipeline Progress</span>
                  <span>{reconProgress}%</span>
                </div>
                <div className="w-full bg-slate-900 rounded-full h-2.5 overflow-hidden border border-slate-800">
                  <div className="bg-indigo-500 h-full transition-all duration-500" style={{ width: `${reconProgress}%` }}></div>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center p-8 bg-slate-900/10 rounded-2xl border border-dashed border-slate-800 text-slate-500 text-xs italic">
              No active recon session.
            </div>
          )}

          {/* Active Exploit Agent Stats Panel */}
          {activeAgentId ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <div className="flex items-center space-x-2">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                  </span>
                  <span className="text-xs font-bold text-slate-300 font-mono">EXPLOIT AGENT ACTIVE</span>
                </div>
                <div className="text-xs text-slate-500 font-mono">Running time: <span className="text-emerald-400 font-bold">{agentElapsed}</span></div>
              </div>

              <div className="bg-slate-900/50 p-4 rounded-xl border border-slate-800 space-y-2">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500 uppercase text-[10px] font-bold">Agent Current State</span>
                  <span className="text-emerald-400 font-mono font-bold truncate max-w-[200px]">{agentCurrentTool || 'Reasoning / Evaluating'}</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed font-mono truncate">
                  {agentLogs.length > 0 ? agentLogs[agentLogs.length - 1] : 'Initializing autonomous exploit loop...'}
                </p>
              </div>
            </div>
          ) : (
            <div className="flex items-center justify-center p-8 bg-slate-900/10 rounded-2xl border border-dashed border-slate-800 text-slate-500 text-xs italic">
              No active exploit agent session.
            </div>
          )}
        </div>
      )}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

        {/* Left Columns */}
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
            <Link href={`/investigations/${investigationId}/exploitation`} className="bg-slate-900 border border-slate-800 hover:bg-slate-800 px-4 py-2 rounded-xl text-xs font-bold transition-all flex items-center space-x-2">
               <svg className="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
               <span>Exploitation</span>
            </Link>
          </div>

          {/* Severity Distribution Chart / Visualization bar */}
          <section className="bg-slate-900 border border-slate-800 p-6 rounded-2xl space-y-4">
             <h3 className="font-bold text-sm text-slate-200 uppercase tracking-wider font-heading">Severity Distribution Chart</h3>
             <div className="w-full flex h-6 rounded-full overflow-hidden border border-slate-950">
               {findings.length === 0 ? (
                 <div className="w-full bg-slate-800 flex items-center justify-center text-slate-500 text-[10px] font-bold">NO FINDINGS YET</div>
               ) : (
                 <>
                   {severityCounts.critical > 0 && <div className="bg-rose-600 transition-all" style={{ width: `${(severityCounts.critical / totalSeverities) * 100}%` }} title={`Critical: ${severityCounts.critical}`}></div>}
                   {severityCounts.high > 0 && <div className="bg-amber-500 transition-all" style={{ width: `${(severityCounts.high / totalSeverities) * 100}%` }} title={`High: ${severityCounts.high}`}></div>}
                   {severityCounts.medium > 0 && <div className="bg-yellow-400 transition-all" style={{ width: `${(severityCounts.medium / totalSeverities) * 100}%` }} title={`Medium: ${severityCounts.medium}`}></div>}
                   {severityCounts.low > 0 && <div className="bg-emerald-500 transition-all" style={{ width: `${(severityCounts.low / totalSeverities) * 100}%` }} title={`Low: ${severityCounts.low}`}></div>}
                   {severityCounts.info > 0 && <div className="bg-sky-400 transition-all" style={{ width: `${(severityCounts.info / totalSeverities) * 100}%` }} title={`Info: ${severityCounts.info}`}></div>}
                 </>
               )}
             </div>
             <div className="flex flex-wrap justify-center gap-4 text-xs font-mono">
               <div className="flex items-center space-x-1.5"><span className="w-3 h-3 rounded bg-rose-600"></span><span className="text-slate-300">Critical ({severityCounts.critical})</span></div>
               <div className="flex items-center space-x-1.5"><span className="w-3 h-3 rounded bg-amber-500"></span><span className="text-slate-300">High ({severityCounts.high})</span></div>
               <div className="flex items-center space-x-1.5"><span className="w-3 h-3 rounded bg-yellow-400"></span><span className="text-slate-300">Medium ({severityCounts.medium})</span></div>
               <div className="flex items-center space-x-1.5"><span className="w-3 h-3 rounded bg-emerald-500"></span><span className="text-slate-300">Low ({severityCounts.low})</span></div>
               <div className="flex items-center space-x-1.5"><span className="w-3 h-3 rounded bg-sky-400"></span><span className="text-slate-300">Info ({severityCounts.info})</span></div>
             </div>
          </section>

          {/* Neo4j Graph Statistics Cards */}
          <section className="grid grid-cols-2 md:grid-cols-4 gap-6">
             <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl text-center space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Hosts</span>
                <div className="text-3xl font-black text-slate-200">{graphStats.hosts}</div>
             </div>
             <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl text-center space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Services</span>
                <div className="text-3xl font-black text-indigo-400">{graphStats.services}</div>
             </div>
             <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl text-center space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Endpoints</span>
                <div className="text-3xl font-black text-sky-400">{graphStats.endpoints}</div>
             </div>
             <div className="bg-slate-900/60 border border-slate-800/80 p-5 rounded-xl text-center space-y-1">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Findings</span>
                <div className="text-3xl font-black text-emerald-400">{graphStats.findings}</div>
             </div>
          </section>

          {/* Terminal / Live Logs Viewer */}
          {(activeReconId || activeAgentId) && (
            <section className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
               <div className="bg-slate-900 px-5 py-3 border-b border-slate-800 flex justify-between items-center">
                  <h3 className="text-xs font-bold text-slate-300 uppercase tracking-widest font-heading flex items-center gap-1.5">
                     <span className="w-2 h-2 bg-rose-500 rounded-full animate-ping"></span>
                     Live Terminal Console Output
                  </h3>
                  <span className="text-[10px] text-slate-500 font-mono">Stream: {activeReconId ? 'RECON' : 'AGENT'}</span>
               </div>
               <div className="p-4 h-64 overflow-y-auto font-mono text-xs text-emerald-400 space-y-2 bg-slate-950">
                  {activeReconId ? (
                     reconLogs.length === 0 ? (
                       <div className="text-slate-600 italic">Waiting for logs...</div>
                     ) : (
                       reconLogs.map((log, idx) => (
                         <div key={idx} className="whitespace-pre-wrap">{log}</div>
                       ))
                     )
                  ) : (
                     agentLogs.length === 0 ? (
                       <div className="text-slate-600 italic">Waiting for agent reasoning logs...</div>
                     ) : (
                       agentLogs.map((log, idx) => (
                         <div key={idx} className="whitespace-pre-wrap">[{new Date().toLocaleTimeString()}] {log}</div>
                       ))
                     )
                  )}
                  <div ref={terminalEndRef}></div>
               </div>
            </section>
          )}

          {/* Active Findings list */}
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

          {/* Chronological Validation Timeline */}
          <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
             <h3 className="font-bold text-sm text-slate-200 uppercase tracking-wider font-heading">Validation Timeline</h3>
             <div className="relative border-l border-slate-800 pl-4 space-y-6">
                {findings.length === 0 ? (
                  <p className="text-slate-500 italic text-xs">No validation events recorded yet.</p>
                ) : (
                  findings.map((f, idx) => (
                    <div key={f.id} className="relative">
                       <span className="absolute -left-[21px] top-1 bg-indigo-500 w-2.5 h-2.5 rounded-full border border-slate-900"></span>
                       <div className="text-[10px] font-mono text-indigo-400">{new Date(f.discovered_at).toLocaleString()}</div>
                       <div className="font-bold text-xs text-slate-200 mt-0.5">{f.vuln_type.toUpperCase()} Discovery</div>
                       <p className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{f.description}</p>
                    </div>
                  ))
                )}
             </div>
          </section>

          {/* Actions grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
             <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-2xl p-6 space-y-4 hover:border-indigo-500/60 transition-all shadow-lg shadow-indigo-500/12">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-200 font-heading">Recon Cycle</h3>
                  <div className={`h-2 w-2 rounded-full ${activeReconId ? 'bg-indigo-500 animate-pulse' : 'bg-slate-700'}`}></div>
                </div>
                <p className="text-slate-400 text-sm">Orchestrate automated discovery across the investigation scope.</p>
                <div className="pt-2">
                  {activeReconId ? (
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
                  <div className={`h-2 w-2 rounded-full ${activeAgentId ? 'bg-indigo-500 animate-pulse' : 'bg-slate-700'}`}></div>
                </div>
                <p className="text-slate-400 text-sm">Autonomous reasoning loop for live target validation.</p>
                <div className="pt-2">
                  {activeAgentId ? (
                    <div className="space-y-3">
                       <Link href={`/investigations/${investigationId}/agent/${activeAgentId}`} className="block text-center bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-bold py-3 rounded-xl text-sm hover:bg-indigo-600/30 transition-all active:scale-95">
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

        {/* Right Sidebar Columns */}
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
                Execution Gate
              </h3>
              <p className="text-slate-400 text-sm mb-4">Approved exploit modules available for execution. Every execution is logged to the immutable audit trail.</p>
              <ActiveExploitApproval investigationId={investigationId as string} />
           </section>

           <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-2xl p-6 shadow-lg shadow-indigo-500/12">
              <h3 className="font-bold text-lg mb-2 text-emerald-500 flex items-center font-heading">
                <svg className="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clipRule="evenodd" /></svg>
                Rules of Engagement
              </h3>
              <p className="text-slate-400 text-sm mb-4">Explicit in-scope and out-of-scope rules for this investigation.</p>
              <ScopeRules investigationId={investigationId as string} />
              <Link href={`/investigations/${investigationId}/exploitation`} className="block mt-4 text-center bg-slate-800 hover:bg-slate-700 text-white font-bold py-2 rounded-xl text-xs transition-all border border-slate-700 shadow-lg active:scale-95">
                View Exploitation & Audit History
              </Link>
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
                    if (!activeReconId) return;
                    cancelRecon(activeReconId).then(() => {
                      setActiveReconId(null);
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
                    if (!activeAgentId) return;
                    stopAgentSession(activeAgentId).then(() => {
                      setActiveAgentId(null);
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
