'use client';

import React, { useState, useMemo } from 'react';
import { Finding, GraphResponse } from '../types/graph';
import FindingRow from './FindingRow';
import FindingDetailModal from './FindingDetailModal';

interface FindingsListProps {
  findings: Finding[];
  graph: GraphResponse;
}

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export default function FindingsList({ findings, graph }: FindingsListProps) {
  // 1. UI states
  const [showDuplicatesAndFPs, setShowDuplicatesAndFPs] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>([]);
  const [selectedVulnTypes, setSelectedVulnTypes] = useState<string[]>([]);
  const [sortBy, setSortBy] = useState<'severity' | 'ai_confidence' | 'discovered_at'>('severity');
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  // 2. Dynamic list of vulnerability types from loaded findings
  const allVulnTypes = useMemo(() => {
    const types = new Set<string>();
    findings.forEach(f => {
      if (f.vuln_type) types.add(f.vuln_type.toLowerCase());
    });
    return Array.from(types).sort();
  }, [findings]);

  // 3. Map findings to targets and tools from graph
  const mappedFindings = useMemo(() => {
    return findings.map(finding => {
      let affectedAsset = '';
      let sourceTool = '';

      // Find affected target in graph
      const hasFindingLink = graph.links.find(
        link => link.target === finding.id && link.type === 'HAS_FINDING'
      );

      if (hasFindingLink) {
        const targetNode = graph.nodes.find(node => node.id === hasFindingLink.source);
        if (targetNode) {
          if (targetNode.labels.includes('Endpoint')) {
            affectedAsset = `Endpoint: [${targetNode.properties.method || 'GET'}] ${targetNode.properties.url || ''}`;
          } else if (targetNode.labels.includes('Parameter')) {
            const paramName = targetNode.properties.name || '';
            const paramLocation = targetNode.properties.location || '';

            // Find parent endpoint if any
            const hasParamLink = graph.links.find(
              link => link.target === targetNode.id && link.type === 'HAS_PARAMETER'
            );
            let endpointUrl = '';
            if (hasParamLink) {
              const endpointNode = graph.nodes.find(node => node.id === hasParamLink.source);
              if (endpointNode) {
                endpointUrl = endpointNode.properties.url || '';
              }
            }

            affectedAsset = `Parameter: ${paramName} (${paramLocation})${endpointUrl ? ` on ${endpointUrl}` : ''}`;
          }
        }
      }

      // Find discovering tool in graph
      const discoveredByLink = graph.links.find(
        link => link.source === finding.id && link.type === 'DISCOVERED_BY'
      );

      if (discoveredByLink) {
        const toolNode = graph.nodes.find(node => node.id === discoveredByLink.target);
        if (toolNode) {
          sourceTool = toolNode.properties.name || '';
        }
      }

      return {
        finding,
        affectedAsset,
        sourceTool,
      };
    });
  }, [findings, graph]);

  // 4. Filtering logic
  const filteredFindings = useMemo(() => {
    return mappedFindings.filter(({ finding, affectedAsset }) => {
      // a. Default exclusion of DUPLICATE and FALSE_POSITIVE
      if (!showDuplicatesAndFPs) {
        if (finding.status === 'DUPLICATE' || finding.status === 'FALSE_POSITIVE') {
          return false;
        }
      }

      // b. Text search on vuln_type, description, affected asset
      if (searchQuery.trim() !== '') {
        const query = searchQuery.toLowerCase();
        const matchesVulnType = finding.vuln_type?.toLowerCase().includes(query);
        const matchesDescription = finding.description?.toLowerCase().includes(query);
        const matchesAsset = affectedAsset?.toLowerCase().includes(query);

        if (!matchesVulnType && !matchesDescription && !matchesAsset) {
          return false;
        }
      }

      // c. Multi-select Severities
      if (selectedSeverities.length > 0) {
        if (!selectedSeverities.includes(finding.severity.toLowerCase())) {
          return false;
        }
      }

      // d. Multi-select Statuses
      if (selectedStatuses.length > 0) {
        if (!selectedStatuses.includes(finding.status.toUpperCase())) {
          return false;
        }
      }

      // e. Multi-select Vuln Types
      if (selectedVulnTypes.length > 0) {
        if (!selectedVulnTypes.includes(finding.vuln_type.toLowerCase())) {
          return false;
        }
      }

      return true;
    });
  }, [mappedFindings, showDuplicatesAndFPs, searchQuery, selectedSeverities, selectedStatuses, selectedVulnTypes]);

  // 5. Sorting logic
  const sortedFindings = useMemo(() => {
    const list = [...filteredFindings];

    list.sort((a, b) => {
      if (sortBy === 'severity') {
        const severityDiff =
          (severityOrder[a.finding.severity.toLowerCase()] ?? 5) -
          (severityOrder[b.finding.severity.toLowerCase()] ?? 5);

        if (severityDiff !== 0) return severityDiff;

        // secondary sort: ai_confidence ascending (matches review-queue order)
        const confA = a.finding.ai_confidence ?? 0;
        const confB = b.finding.ai_confidence ?? 0;
        return confA - confB;
      }

      if (sortBy === 'ai_confidence') {
        const confA = a.finding.ai_confidence ?? 0;
        const confB = b.finding.ai_confidence ?? 0;
        return confA - confB; // ascending
      }

      if (sortBy === 'discovered_at') {
        const timeA = new Date(a.finding.discovered_at).getTime();
        const timeB = new Date(b.finding.discovered_at).getTime();
        return timeB - timeA; // newest first
      }

      return 0;
    });

    return list;
  }, [filteredFindings, sortBy]);

  // 6. Modal details selection
  const selectedItem = useMemo(() => {
    if (!selectedFindingId) return null;
    return mappedFindings.find(item => item.finding.id === selectedFindingId) || null;
  }, [selectedFindingId, mappedFindings]);

  // Helper toggle functions
  const handleToggleSeverity = (severity: string) => {
    setSelectedSeverities(prev =>
      prev.includes(severity) ? prev.filter(s => s !== severity) : [...prev, severity]
    );
  };

  const handleToggleStatus = (status: string) => {
    setSelectedStatuses(prev =>
      prev.includes(status) ? prev.filter(s => s !== status) : [...prev, status]
    );
  };

  const handleToggleVulnType = (type: string) => {
    setSelectedVulnTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    );
  };

  return (
    <div className="space-y-6">
      {/* Filters Control Panel */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <h3 className="font-bold text-slate-200 font-heading flex items-center">
            <svg className="w-5 h-5 text-indigo-400 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 8.293A1 1 0 013 7.586V4z" />
            </svg>
            Filter & Sort Controls
          </h3>

          {/* Toggle show duplicates */}
          <label className="flex items-center space-x-3 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={showDuplicatesAndFPs}
              onChange={e => setShowDuplicatesAndFPs(e.target.checked)}
              className="w-4 h-4 rounded border-slate-800 bg-slate-950 text-indigo-600 focus:ring-0 focus:ring-offset-0"
            />
            <span className="text-xs text-slate-400 font-bold uppercase tracking-wider">
              Show duplicates & false positives
            </span>
          </label>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Search Box */}
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Text Search</label>
            <input
              type="text"
              placeholder="Search vuln type, description..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white outline-none focus:border-indigo-500 text-xs"
            />
          </div>

          {/* Severity Multi-select Checklist */}
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Severity</label>
            <div className="flex flex-wrap gap-2 pt-1">
              {['critical', 'high', 'medium', 'low', 'info'].map(severity => {
                const active = selectedSeverities.includes(severity);
                return (
                  <button
                    key={severity}
                    onClick={() => handleToggleSeverity(severity)}
                    className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-all border ${
                      active
                        ? 'bg-indigo-600 border-indigo-500 text-white shadow-md shadow-indigo-600/10'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {severity}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Status Multi-select Checklist */}
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Status</label>
            <div className="flex flex-wrap gap-2 pt-1">
              {['HUMAN_CONFIRMED', 'CORROBORATED', 'AI_VALIDATED', 'UNCONFIRMED', 'FALSE_POSITIVE', 'DUPLICATE'].map(status => {
                const active = selectedStatuses.includes(status);
                // Don't show FALSE_POSITIVE or DUPLICATE buttons if toggle is off, to keep clean
                if (!showDuplicatesAndFPs && (status === 'FALSE_POSITIVE' || status === 'DUPLICATE')) return null;

                return (
                  <button
                    key={status}
                    onClick={() => handleToggleStatus(status)}
                    className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider transition-all border ${
                      active
                        ? 'bg-emerald-600 border-emerald-500 text-white shadow-md'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {status.replace('_', ' ')}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Sort By Dropdown */}
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Sort Order</label>
            <select
              value={sortBy}
              onChange={e => setSortBy(e.target.value as any)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-2.5 text-white outline-none focus:border-indigo-500 text-xs"
            >
              <option value="severity">Severity (High → Low)</option>
              <option value="ai_confidence">AI Confidence (Low → High)</option>
              <option value="discovered_at">Discovery Date (Newest → Oldest)</option>
            </select>
          </div>
        </div>

        {/* Dynamic Vuln Types Multi-select */}
        {allVulnTypes.length > 0 && (
          <div className="space-y-1.5 border-t border-slate-800/60 pt-4">
            <label className="text-[10px] font-bold text-slate-500 uppercase tracking-widest block">Vulnerability Types</label>
            <div className="flex flex-wrap gap-2 max-h-24 overflow-y-auto pt-1">
              {allVulnTypes.map(type => {
                const active = selectedVulnTypes.includes(type);
                return (
                  <button
                    key={type}
                    onClick={() => handleToggleVulnType(type)}
                    className={`px-2 py-0.5 rounded text-[10px] font-mono transition-all border ${
                      active
                        ? 'bg-rose-900/30 border-rose-700 text-rose-300'
                        : 'bg-slate-950/40 border-slate-800/80 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    {type.toUpperCase()}
                  </button>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Main Table/List */}
      <div className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <div className="p-6 border-b border-slate-800 bg-slate-900/40 flex justify-between items-center">
          <h2 className="font-bold text-lg flex items-center font-heading">
            <span className="w-2.5 h-2.5 bg-indigo-500 rounded-full mr-2"></span>
            Scan Findings ({sortedFindings.length} of {findings.length})
          </h2>
        </div>

        {sortedFindings.length === 0 ? (
          <div className="p-16 text-center text-slate-500">
            <svg className="w-12 h-12 text-slate-700 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-sm italic">
              No findings yet — start a recon session or agent session to begin discovering vulnerabilities
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/25 text-[10px] font-bold text-slate-400 uppercase tracking-widest font-mono">
                  <th className="p-4">Severity</th>
                  <th className="p-4">Vulnerability Type</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">AI Confidence</th>
                  <th className="p-4">Affected Asset</th>
                  <th className="p-4">Age</th>
                  <th className="p-4">Source Tool</th>
                </tr>
              </thead>
              <tbody>
                {sortedFindings.map(({ finding, affectedAsset, sourceTool }) => (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    affectedAsset={affectedAsset}
                    sourceTool={sourceTool}
                    onClick={() => setSelectedFindingId(finding.id)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Expanded Modal */}
      {selectedItem && (
        <FindingDetailModal
          finding={selectedItem.finding}
          affectedAsset={selectedItem.affectedAsset}
          sourceTool={selectedItem.sourceTool}
          onClose={() => setSelectedFindingId(null)}
        />
      )}
    </div>
  );
}
