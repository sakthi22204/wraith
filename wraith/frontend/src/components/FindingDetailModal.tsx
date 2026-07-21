'use client';

import React from 'react';
import { Finding } from '../types/graph';
import SeverityBadge from './SeverityBadge';

interface FindingDetailModalProps {
  finding: Finding;
  affectedAsset: string;
  sourceTool: string;
  onClose: () => void;
}

export default function FindingDetailModal({
  finding,
  affectedAsset,
  sourceTool,
  onClose,
}: FindingDetailModalProps) {
  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">

        {/* Header */}
        <div className="p-6 border-b border-slate-800 bg-slate-900/50 flex justify-between items-center">
          <div>
            <h3 className="text-xl font-bold text-white font-heading truncate max-w-lg">
              {finding.vuln_type.toUpperCase()}
            </h3>
            <p className="text-slate-400 text-xs mt-1 font-mono">ID: {finding.id}</p>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors p-2 text-xl font-bold"
            aria-label="Close modal"
          >
            &times;
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1">
          {/* Metadata Badges */}
          <div className="grid grid-cols-2 gap-4 bg-slate-950/60 p-4 rounded-xl border border-slate-800">
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Severity</span>
              <SeverityBadge severity={finding.severity} />
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Status</span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border inline-block ${
                finding.status === 'HUMAN_CONFIRMED' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' :
                finding.status === 'CORROBORATED' ? 'bg-blue-950 text-blue-400 border-blue-800' :
                finding.status === 'AI_VALIDATED' ? 'bg-yellow-950 text-yellow-400 border-yellow-800' :
                finding.status === 'UNCONFIRMED' ? 'bg-slate-800 text-slate-300 border-slate-700' :
                'bg-slate-950 text-slate-500 border-slate-800 line-through'
              }`}>
                {finding.status}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">AI Confidence</span>
              <span className="text-sm font-mono text-slate-200">
                {finding.ai_confidence !== undefined && finding.ai_confidence !== null
                  ? `${Math.round(finding.ai_confidence * 100)}%`
                  : 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-[10px] font-bold text-slate-500 uppercase block mb-1">Source Tool</span>
              <span className="text-sm text-indigo-400 font-mono font-bold">
                {sourceTool || 'Unknown'}
              </span>
            </div>
          </div>

          {/* Affected Asset */}
          <div>
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Affected Asset</h4>
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-200 break-all">
              {affectedAsset || 'Unknown target asset'}
            </div>
          </div>

          {/* Description */}
          <div>
            <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Description</h4>
            <p className="text-sm text-slate-300 leading-relaxed bg-slate-950 border border-slate-800 rounded-xl p-4 whitespace-pre-wrap">
              {finding.description}
            </p>
          </div>

          {/* CVSS Vector */}
          {finding.cvss_vector && (
            <div>
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">CVSS Vector</h4>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-amber-500">
                {finding.cvss_vector}
              </div>
            </div>
          )}

          {/* AI Reasoning */}
          {finding.ai_reasoning && (
            <div>
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">AI Validation Reasoning</h4>
              <p className="text-sm text-slate-300 leading-relaxed bg-slate-950 border border-slate-800 rounded-xl p-4 whitespace-pre-wrap">
                {finding.ai_reasoning}
              </p>
            </div>
          )}

          {/* Corroborating Sources */}
          {finding.corroborating_sources && finding.corroborating_sources.length > 0 && (
            <div>
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Corroborating Evidence Sources</h4>
              <ul className="list-disc pl-5 space-y-1 text-sm text-slate-300">
                {finding.corroborating_sources.map((source, index) => (
                  <li key={index} className="font-mono text-xs text-blue-400 break-all">{source}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Evidence */}
          {finding.evidence && (
            <div>
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Raw Proof of Concept / Evidence</h4>
              <pre className="text-xs text-slate-200 font-mono bg-slate-950 border border-slate-800 rounded-xl p-4 overflow-x-auto max-h-60 whitespace-pre">
                {finding.evidence}
              </pre>
            </div>
          )}

          {/* Discovered At */}
          <div className="text-[10px] text-slate-500 font-mono">
            Discovered at: {new Date(finding.discovered_at).toLocaleString()}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-xl text-sm font-bold transition-all border border-slate-700 active:scale-95"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
}
