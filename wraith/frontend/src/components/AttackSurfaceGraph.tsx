'use client';

import React, { useCallback, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Node, Link, GraphResponse, Severity } from '../types/graph';

interface AttackSurfaceGraphProps {
  data: GraphResponse;
  onNodeClick: (node: Node) => void;
}

const TYPE_COLORS: Record<string, string> = {
  Program: '#3b82f6', // blue-500
  Host: '#10b981',    // emerald-500
  Port: '#f59e0b',    // amber-500
  Service: '#8b5cf6', // violet-500
  Endpoint: '#06b6d4', // cyan-500
  Parameter: '#64748b', // slate-500
  Finding: '#ef4444',  // red-500
  CVE: '#d946ef',      // fuchsia-500
  Tool: '#f97316',     // orange-500
  ScanSession: '#ec4899', // pink-500
};

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#7f1d1d', // red-900
  high: '#ef4444',     // red-500
  medium: '#f97316',   // orange-500
  low: '#fbbf24',      // amber-400
  info: '#3b82f6',     // blue-500
};

const SEVERITY_SIZES: Record<Severity, number> = {
  critical: 10,
  high: 8,
  medium: 6,
  low: 4,
  info: 3,
};

export default function AttackSurfaceGraph({ data, onNodeClick }: AttackSurfaceGraphProps) {
  const getNodeColor = useCallback((node: Node) => {
    const labels = node.labels || [];
    const type = labels[0];

    if (type === 'Finding') {
      const severity = (node.properties.severity || 'info').toLowerCase() as Severity;
      return SEVERITY_COLORS[severity] || TYPE_COLORS.Finding;
    }

    return TYPE_COLORS[type] || '#94a3b8';
  }, []);

  const getNodeVal = useCallback((node: Node) => {
    const labels = node.labels || [];
    if (labels.includes('Finding')) {
      const severity = (node.properties.severity || 'info').toLowerCase() as Severity;
      return SEVERITY_SIZES[severity] || 4;
    }
    if (labels.includes('Program')) return 8;
    return 4;
  }, []);

  const getNodeLabel = useCallback((node: Node): string => {
    const labels = node.labels || [];
    const type = labels[0] || '';
    const raw = node.properties.name || node.properties.value || node.properties.url || node.properties.path || '';
    const name = typeof raw === 'string' ? raw : String(raw);
    return name.length > 24 ? name.slice(0, 22) + '…' : name;
  }, []);

  const nodeCanvasObject = useCallback((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const color = getNodeColor(node as Node);
    const val = getNodeVal(node as Node);
    const fontSize = Math.max(10 / globalScale, 2);
    const label = getNodeLabel(node as Node);
    const nodeR = Math.sqrt(val) * 1.2;

    ctx.beginPath();
    ctx.arc(node.x, node.y, nodeR, 0, 2 * Math.PI);
    ctx.fillStyle = color;
    ctx.fill();

    if (label) {
      ctx.font = `${fontSize}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle = 'rgba(226,232,240,0.85)';
      ctx.fillText(label, node.x, node.y + nodeR + 1 / globalScale);
    }
  }, [getNodeColor, getNodeVal, getNodeLabel]);

  return (
    <div className="w-full h-full bg-slate-900 rounded-lg overflow-hidden border border-slate-700">
      <ForceGraph2D
        graphData={data}
        nodeCanvasObject={nodeCanvasObject}
        nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D, globalScale: number) => {
          const val = getNodeVal(node as Node);
          const nodeR = Math.sqrt(val) * 1.2;
          ctx.beginPath();
          ctx.arc(node.x, node.y, nodeR, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
        }}
        nodeLabel={(node: Node) => {
          const type = node.labels?.[0] || 'Unknown';
          const name = node.properties.name || node.properties.value || node.properties.url || node.id;
          return `${type}: ${name}`;
        }}
        nodeColor={getNodeColor}
        nodeVal={getNodeVal}
        linkDirectionalArrowLength={3.5}
        linkDirectionalArrowRelPos={1}
        linkCurvature={0.25}
        onNodeClick={(node: Node) => onNodeClick(node)}
        backgroundColor="#0f172a"
        linkColor={() => '#334155'}
      />
    </div>
  );
}
