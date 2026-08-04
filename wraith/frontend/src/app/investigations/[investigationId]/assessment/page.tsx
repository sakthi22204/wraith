'use client';

import React, { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { toast } from 'sonner';
import { config } from '@/lib/config';
import Skeleton from '@/components/Skeleton';

export default function AssessmentPage() {
  const { investigationId } = useParams();
  const router = useRouter();
  const [assessment, setAssessment] = useState<any>(null);
  const [approvalStatus, setApprovalStatus] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isApproving, setIsApproving] = useState(false);

  const loadData = async () => {
    try {
      // 1. Fetch assessment report
      const assessUrl = `${config.assessmentUrl}/api/v1/assessments/${investigationId}`;
      const assessResp = await fetch(assessUrl);
      const assessData = await assessResp.json();
      setAssessment(assessData);

      // 2. Fetch global approval status
      const approveUrl = `${config.exploitRunnerUrl}/api/v1/exploit/investigations/${investigationId}/approval-status`;
      const approveResp = await fetch(approveUrl);
      const approveData = await approveResp.json();
      setApprovalStatus(approveData);
    } catch (e) {
      console.error('Failed to load assessment data:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [investigationId]);

  const handleGlobalApprove = async () => {
    setIsApproving(true);
    try {
      const url = `/api/exploit/investigations/${investigationId}/approve`;
      const resp = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        }
      });
      const data = await resp.json();
      if (resp.ok) {
        toast.success('Investigation globally approved! Automated exploit pipeline unlocked.');
        setApprovalStatus({ approved: true, approved_by: 'Global Approval' });
      } else {
        toast.error(`Approval failed: ${data.detail || 'Unknown error'}`);
      }
    } catch (e) {
      toast.error('Network error during global approval.');
    } finally {
      setIsApproving(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-8 max-w-5xl mx-auto py-8">
        <Skeleton className="h-10 w-1/3" />
        <Skeleton className="h-40 w-full rounded-2xl" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <Skeleton className="h-64 w-full rounded-2xl" />
          <Skeleton className="h-64 w-full rounded-2xl" />
        </div>
      </div>
    );
  }

  const findingsSummary = assessment?.findings_summary || {};
  const totalFindings = Object.values(findingsSummary).reduce((a: any, b: any) => a + b, 0) as number;

  return (
    <div className="space-y-8 max-w-5xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
      {/* Header */}
      <div>
        <Link href={`/investigations/${investigationId}`} className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block font-sans">← Back to Dashboard</Link>
        <h1 className="text-4xl font-bold tracking-tight">Investigation Security Assessment</h1>
        <p className="text-slate-400 text-sm mt-1">Automatic vulnerability assessment, CVE mapping, target prioritization, and risk scores.</p>
      </div>

      {/* Global Approval Banner */}
      <div className={`p-6 rounded-2xl border ${
        approvalStatus?.approved
          ? 'bg-emerald-950/20 border-emerald-500/30'
          : 'bg-amber-950/20 border-amber-500/30 animate-pulse'
      } flex flex-col md:flex-row justify-between items-center gap-4`}>
        <div className="space-y-1">
          <h2 className={`font-bold text-lg ${approvalStatus?.approved ? 'text-emerald-400' : 'text-amber-400'}`}>
            {approvalStatus?.approved ? '✓ Investigation Globally Approved' : '⚠️ Exploit Investigation Approval Required'}
          </h2>
          <p className="text-xs text-slate-400 max-w-xl">
            {approvalStatus?.approved
              ? `Globally approved by ${approvalStatus.approved_by || 'Administrator'}. The AI agent can automatically execute live validations and modules without individual prompts.`
              : 'Approve the exploit validation phase for this investigation. This single approval applies globally; the agent will run validation plans automatically.'}
          </p>
        </div>
        {!approvalStatus?.approved && (
          <button
            onClick={handleGlobalApprove}
            disabled={isApproving}
            className="bg-amber-500 hover:bg-amber-400 text-black px-6 py-3 rounded-xl font-bold transition-all whitespace-nowrap active:scale-95 shadow-lg shadow-amber-500/10"
          >
            {isApproving ? 'Approving...' : 'Approve Exploit Investigation'}
          </button>
        )}
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center space-y-2">
          <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Risk Score</label>
          <div className="text-4xl font-black text-rose-500 font-heading">
            {assessment?.risk_score?.toFixed(1) || '0.0'} <span className="text-xs text-slate-500 font-medium">/ 10</span>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center space-y-2">
          <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Technologies</label>
          <div className="text-4xl font-black text-indigo-400 font-heading">
            {assessment?.technologies?.length || 0}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center space-y-2">
          <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Target Assets</label>
          <div className="text-4xl font-black text-sky-400 font-heading">
            {assessment?.hosts_count || 0} <span className="text-xs text-slate-500 font-medium">Hosts</span>
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 text-center space-y-2">
          <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Active Findings</label>
          <div className="text-4xl font-black text-emerald-400 font-heading">
            {totalFindings}
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

        {/* Recommended Validation Plan */}
        <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 border border-indigo-500/10 rounded-2xl p-6 space-y-4">
          <h3 className="font-bold text-lg text-slate-200 font-heading flex items-center">
            <span className="w-2.5 h-2.5 bg-indigo-500 rounded-full mr-2"></span>
            Recommended Validation Order
          </h3>
          <div className="space-y-4">
            {assessment?.validation_plan?.length === 0 ? (
              <p className="text-sm text-slate-500 italic">No validation tasks recommended yet.</p>
            ) : (
              assessment?.validation_plan?.map((task: any) => (
                <div key={task.step} className="flex gap-4 items-start">
                  <div className="bg-indigo-600/10 text-indigo-400 w-8 h-8 rounded-full font-bold flex items-center justify-center shrink-0 border border-indigo-500/20 text-xs">
                    {task.step}
                  </div>
                  <div className="space-y-1">
                    <div className="font-bold text-sm text-slate-200">
                      {task.action.toUpperCase()} <span className="text-slate-500 font-normal">on</span> {task.target}
                    </div>
                    <p className="text-xs text-slate-400">{task.reason}</p>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        {/* Target Prioritization & CVE correlation */}
        <div className="space-y-8">
          <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 border border-indigo-500/10 rounded-2xl p-6 space-y-4">
            <h3 className="font-bold text-lg text-slate-200 font-heading flex items-center">
              <span className="w-2.5 h-2.5 bg-rose-500 rounded-full mr-2"></span>
              Prioritized Targets
            </h3>
            <div className="divide-y divide-slate-800">
              {assessment?.prioritized_targets?.length === 0 ? (
                <p className="text-sm text-slate-500 italic">No targets identified for prioritization.</p>
              ) : (
                assessment?.prioritized_targets?.slice(0, 5).map((t: any) => (
                  <div key={t.target_id} className="py-3 flex justify-between items-center">
                    <div>
                      <div className="font-bold text-xs text-slate-200 truncate max-w-[220px]">{t.host}</div>
                      <span className="text-[10px] text-slate-500 font-mono block mt-0.5">{t.reason}</span>
                    </div>
                    <span className="bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-bold px-2 py-0.5 rounded">
                      Risk: {t.risk_score?.toFixed(1)}
                    </span>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 border border-indigo-500/10 rounded-2xl p-6 space-y-4">
            <h3 className="font-bold text-lg text-slate-200 font-heading flex items-center">
              <span className="w-2.5 h-2.5 bg-sky-500 rounded-full mr-2"></span>
              Correlated CVEs
            </h3>
            <div className="divide-y divide-slate-800">
              {assessment?.correlated_cves?.length === 0 ? (
                <p className="text-sm text-slate-500 italic">No CVEs correlated with running services.</p>
              ) : (
                assessment?.correlated_cves?.map((cve: any) => (
                  <div key={cve.cve_id} className="py-3 flex justify-between items-center">
                    <div>
                      <div className="font-bold text-xs text-slate-200">{cve.cve_id}</div>
                      <span className="text-[10px] text-slate-400 block mt-0.5">{cve.title}</span>
                    </div>
                    <span className="text-[10px] text-slate-500 bg-slate-950 border border-slate-800 px-2 py-0.5 rounded">
                      CVSS {cve.cvss_score}
                    </span>
                  </div>
                ))
              )}
            </div>
          </section>
        </div>

      </div>
    </div>
  );
}
