'use client';

import React, { useEffect, useState } from 'react';
import { fetchScopeRules, addScopeRule } from '@/lib/exploitApi';
import { errorMessage } from '@/lib/apiError';
import { ScopeRule } from '@/types/graph';
import Skeleton from './Skeleton';

interface ScopeRulesProps {
  investigationId: string;
}

export default function ScopeRules({ investigationId }: ScopeRulesProps) {
  const [rules, setRules] = useState<ScopeRule[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pattern, setPattern] = useState('');
  const [ruleType, setRuleType] = useState<'allow' | 'deny'>('allow');
  const [allowAggressive, setAllowAggressive] = useState(false);

  const loadRules = async () => {
    try {
      const data = await fetchScopeRules(investigationId);
      setRules(data);
      setError(null);
    } catch (e) {
      console.error(e);
      setError(errorMessage(e, 'Could not load scope rules.'));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, [investigationId]);

  const allowRules = rules.filter(r => r.rule_type === 'allow');
  const denyRules = rules.filter(r => r.rule_type === 'deny');
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pattern.trim() || isSubmitting) return;
    setIsSubmitting(true);
    try {
      await addScopeRule(investigationId, pattern.trim(), ruleType, allowAggressive);
      setPattern('');
      setAllowAggressive(false);
      setRuleType('allow');
      await loadRules();
    } catch (err) {
      console.error(err);
      setError(errorMessage(err, 'Could not add scope rule.'));
    } finally {
      setIsSubmitting(false);
    }
  };


  return (
    <div className="space-y-4">
      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-1/3" />
          <Skeleton className="h-16 w-full rounded-xl" />
          <Skeleton className="h-16 w-full rounded-xl" />
        </div>
      ) : error ? (
        <p className="text-xs text-slate-500 italic">{error}</p>
      ) : rules.length === 0 ? (
        <p className="text-xs text-slate-500 italic">
          No explicit scope rules defined. Targets fall back to backend enforcement defaults.
        </p>
      ) : (
        <div className="space-y-4">
          <div className="space-y-2">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Allowed (In-Scope)</div>
            {allowRules.length === 0 ? (
              <p className="text-xs text-slate-600 italic">No allow rules</p>
            ) : (
              allowRules.map(rule => (
                <div key={rule.id} className="bg-slate-950 border border-emerald-900/40 rounded-lg px-3 py-2 flex justify-between items-center">
                  <span className="text-xs font-mono text-emerald-400 truncate">{rule.pattern}</span>
                  <span className="text-[9px] font-bold uppercase text-emerald-500/80 ml-2 shrink-0">allow</span>
                </div>
              ))
            )}
          </div>
          <div className="space-y-2">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Denied (Out-of-Scope)</div>
            {denyRules.length === 0 ? (
              <p className="text-xs text-slate-600 italic">No deny rules</p>
            ) : (
              denyRules.map(rule => (
                <div key={rule.id} className="bg-slate-950 border border-red-900/40 rounded-lg px-3 py-2 flex justify-between items-center">
                  <span className="text-xs font-mono text-red-400 truncate">{rule.pattern}</span>
                  <span className="text-[9px] font-bold uppercase text-red-500/80 ml-2 shrink-0">deny</span>
                </div>
              ))
            )}
          </div>
          <p className="text-[10px] text-slate-600 italic">
            Deny rules always win; backend executor enforces scope authoritatively.
          </p>
          <div className="mt-6 pt-6 border-t border-slate-800/50 space-y-3">
            <div className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">Add Scope Rule</div>
            <form onSubmit={handleSubmit} className="space-y-3">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="pattern (e.g., example.com, *.example.com, 10.0.0.0/8)"
                  className="flex-1 bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-indigo-500/50"
                />
                <select
                  value={ruleType}
                  onChange={(e) => setRuleType(e.target.value as 'allow' | 'deny')}
                  className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500/50"
                >
                  <option value="allow">allow</option>
                  <option value="deny">deny</option>
                </select>
              </div>
              <label className="flex items-center gap-2 text-xs text-slate-400">
                <input
                  type="checkbox"
                  checked={allowAggressive}
                  onChange={(e) => setAllowAggressive(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950"
                />
                Allow aggressive scanning
              </label>
              <button
                type="submit"
                disabled={isSubmitting || !pattern.trim()}
                className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white px-3 py-1.5 rounded text-xs font-bold transition-all"
              >
                {isSubmitting ? 'Adding...' : 'Add Rule'}
              </button>
            </form>
          </div>

        </div>
      )}
    </div>
  );
}
