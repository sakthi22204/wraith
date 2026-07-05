import React from 'react';
import SeverityBadge from './SeverityBadge';

interface AgentStepCardProps {
  step: any;
}

export default function AgentStepCard({ step }: AgentStepCardProps) {
  // Determine event type based on keys in the step object
  // Based on routes.py: await streams[session_id].put(json.dumps(output))
  // output is { node_name: { updates } }

  const nodeName = Object.keys(step)[0];
  const updates = step[nodeName];

  if (nodeName === 'reason') {
    const log = updates.reasoning_log?.[0] || '';
    const isToolCall = updates.next_tool !== undefined;

    return (
      <div className="bg-slate-800 border-l-4 border-blue-500 p-4 rounded-r shadow-sm mb-4">
        <div className="text-xs font-bold text-blue-400 uppercase mb-1">Reasoning</div>
        <div className="text-slate-200 text-sm whitespace-pre-wrap">{log}</div>
        {isToolCall && (
          <div className="mt-3 bg-slate-900 p-2 rounded border border-slate-700">
            <div className="text-xs font-semibold text-slate-500 uppercase mb-1">Proposed Tool</div>
            <div className="text-amber-400 font-mono text-xs">
              {updates.next_tool}({JSON.stringify(updates.next_tool_params)})
            </div>
          </div>
        )}
      </div>
    );
  }

  if (nodeName === 'call_tool') {
    const log = updates.reasoning_log?.[0] || '';
    const result = updates.last_tool_result;

    return (
      <div className="bg-slate-800 border-l-4 border-amber-500 p-4 rounded-r shadow-sm mb-4">
        <div className="text-xs font-bold text-amber-400 uppercase mb-1">Tool Execution</div>
        <div className="text-slate-200 text-sm italic mb-2">{log}</div>
        <div className="bg-slate-900 p-2 rounded border border-slate-700 max-h-32 overflow-y-auto">
          <pre className="text-[10px] text-slate-400 font-mono whitespace-pre-wrap">{result}</pre>
        </div>
      </div>
    );
  }

  if (nodeName === 'record_finding') {
    const finding = updates.findings_this_session?.[0];
    if (!finding) return null;

    return (
      <div className="bg-slate-800 border-l-4 border-red-500 p-4 rounded-r shadow-lg mb-4 ring-1 ring-red-500/50">
        <div className="flex justify-between items-start mb-2">
          <div className="text-xs font-bold text-red-400 uppercase">Finding Recorded</div>
          <SeverityBadge severity={finding.severity} />
        </div>
        <h3 className="text-slate-100 font-bold text-sm mb-1">{finding.vuln_type}</h3>
        <p className="text-slate-300 text-xs mb-1">{finding.description}</p>
        <div className="text-[10px] text-slate-500 font-mono uppercase">ID: {finding.id}</div>
      </div>
    );
  }

  if (nodeName === 'propose_exploit') {
     const log = updates.reasoning_log?.[0] || '';
     return (
      <div className="bg-slate-800 border-l-4 border-purple-500 p-4 rounded-r shadow-sm mb-4">
        <div className="text-xs font-bold text-purple-400 uppercase mb-1">Active Exploit Proposal</div>
        <div className="text-slate-200 text-sm font-semibold">{log}</div>
      </div>
    );
  }

  // Generic fallback for other nodes like interpret, fetch_context
  return (
    <div className="bg-slate-800/50 border-l-4 border-slate-600 p-3 rounded-r mb-4">
      <div className="text-[10px] font-bold text-slate-500 uppercase mb-1">{nodeName}</div>
      <div className="text-slate-400 text-xs truncate">{JSON.stringify(updates)}</div>
    </div>
  );
}
