import React from 'react';
import { Severity } from '../types/graph';

interface SeverityBadgeProps {
  severity: string;
}

const COLORS: Record<string, string> = {
  critical: 'bg-red-900 text-red-100 border-red-700',
  high: 'bg-red-600 text-white border-red-500',
  medium: 'bg-orange-500 text-white border-orange-400',
  low: 'bg-amber-400 text-amber-900 border-amber-300',
  info: 'bg-blue-500 text-white border-blue-400',
};

export default function SeverityBadge({ severity }: SeverityBadgeProps) {
  const normalized = severity.toLowerCase();
  const colorClass = COLORS[normalized] || 'bg-slate-500 text-white border-slate-400';

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase border ${colorClass}`}>
      {severity}
    </span>
  );
}
