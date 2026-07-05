'use client';

import React from 'react';
import { Node } from '../types/graph';
import SeverityBadge from './SeverityBadge';

interface NodeDetailsPanelProps {
  node: Node | null;
  onClose: () => void;
}

export default function NodeDetailsPanel({ node, onClose }: NodeDetailsPanelProps) {
  if (!node) return null;

  const type = node.labels[0] || 'Unknown';

  return (
    <div className="absolute right-4 top-4 bottom-4 w-80 bg-slate-800 border border-slate-700 rounded-lg shadow-xl p-4 overflow-y-auto z-10 text-slate-200">
      <div className="flex justify-between items-center mb-4 border-bottom border-slate-700 pb-2">
        <h2 className="text-xl font-bold">{type} Details</h2>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-white transition-colors"
        >
          ✕
        </button>
      </div>

      <div className="space-y-4">
        {Object.entries(node.properties).map(([key, value]) => (
          <div key={key}>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              {key.replace(/_/g, ' ')}
            </div>
            <div className="text-sm bg-slate-900 rounded p-2 border border-slate-700 break-words">
              {key === 'severity' ? (
                <SeverityBadge severity={value} />
              ) : (
                String(value)
              )}
            </div>
          </div>
        ))}

        <div>
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
            System ID
          </div>
          <div className="text-xs font-mono bg-slate-900 rounded p-2 border border-slate-700 break-all">
            {node.id}
          </div>
        </div>
      </div>
    </div>
  );
}
