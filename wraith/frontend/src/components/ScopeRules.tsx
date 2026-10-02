'use client';

import React, { useEffect, useState } from 'react';
import { fetchScopeRules } from '@/lib/exploitApi';
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
            Read-only view. Deny rules always win; backend executor enforces scope authoritatively.
          </p>
        </div>
      )}
    </div>
  );
}
