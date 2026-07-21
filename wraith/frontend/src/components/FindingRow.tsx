'use client';

import React from 'react';
import { Finding } from '../types/graph';
import SeverityBadge from './SeverityBadge';

interface FindingRowProps {
  finding: Finding;
  affectedAsset: string;
  sourceTool: string;
  onClick: () => void;
}

export function getRelativeTime(dateStr: string): string {
  try {
    const now = new Date();
    const discovered = new Date(dateStr);
    const diffMs = now.getTime() - discovered.getTime();
    if (isNaN(diffMs)) return 'Unknown time';
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  } catch {
    return 'Unknown time';
  }
}

export default function FindingRow({
  finding,
  affectedAsset,
  sourceTool,
  onClick,
}: FindingRowProps) {
  const isMuted = finding.status === 'FALSE_POSITIVE' || finding.status === 'DUPLICATE';

  return (
    <tr
      onClick={onClick}
      className="hover:bg-slate-800/40 transition-colors cursor-pointer border-b border-slate-800/80 text-sm align-middle"
    >
      {/* Severity */}
      <td className="p-4 whitespace-nowrap">
        <SeverityBadge severity={finding.severity} />
      </td>

      {/* Vuln Type */}
      <td className="p-4 font-bold text-slate-200">
        <span className={isMuted ? 'line-through text-slate-500' : ''}>
          {finding.vuln_type.toUpperCase()}
        </span>
      </td>

      {/* Status */}
      <td className="p-4 whitespace-nowrap">
        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
          finding.status === 'HUMAN_CONFIRMED' ? 'bg-emerald-950/80 text-emerald-400 border-emerald-900' :
          finding.status === 'CORROBORATED' ? 'bg-blue-950/80 text-blue-400 border-blue-900' :
          finding.status === 'AI_VALIDATED' ? 'bg-yellow-950/80 text-yellow-400 border-yellow-900' :
          finding.status === 'UNCONFIRMED' ? 'bg-slate-800 text-slate-300 border-slate-700' :
          'bg-slate-950 text-slate-500 border-slate-900 line-through'
        }`}>
          {finding.status}
        </span>
      </td>

      {/* AI Confidence */}
      <td className="p-4 whitespace-nowrap font-mono text-xs text-slate-300">
        {finding.ai_confidence !== undefined && finding.ai_confidence !== null
          ? `${Math.round(finding.ai_confidence * 100)}%`
          : 'N/A'}
      </td>

      {/* Affected Endpoint/Parameter */}
      <td className="p-4 text-xs font-mono text-slate-300 break-all max-w-xs md:max-w-md">
        {affectedAsset || '—'}
      </td>

      {/* Discovered At */}
      <td className="p-4 whitespace-nowrap text-xs text-slate-400">
        {getRelativeTime(finding.discovered_at)}
      </td>

      {/* Source Tool */}
      <td className="p-4 whitespace-nowrap text-xs text-indigo-400 font-bold font-mono">
        {sourceTool || 'Unknown'}
      </td>
    </tr>
  );
}
