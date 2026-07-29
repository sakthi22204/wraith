'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { fetchGraph } from '@/lib/graphApi';
import { GraphResponse, Node } from '@/types/graph';
import dynamic from 'next/dynamic';
import NodeDetailsPanel from '@/components/NodeDetailsPanel';

// Load Force Graph dynamically to avoid SSR window error
const AttackSurfaceGraph = dynamic(() => import('@/components/AttackSurfaceGraph'), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-full bg-slate-900 rounded-lg border border-slate-700">
      <div className="text-slate-500 animate-pulse">Initializing 2D WebGL Engine...</div>
    </div>
  )
});

export default function GraphPage() {
  const params = useParams();
  const investigationId = params?.investigationId as string;
  const [data, setData] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);

  useEffect(() => {
    if (!investigationId) return;
    const loadData = async () => {
      try {
        setLoading(true);
        const graphData = await fetchGraph(investigationId);
        setData(graphData);
        setError(null);
      } catch (e) {
        console.error('Failed to load graph', e);
        setError('Could not load attack surface graph. Verify that graph_db is running.');
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [investigationId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[70vh]">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-indigo-500 mb-4"></div>
        <div className="text-slate-400 font-medium">Reconstructing attack surface model...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-900/50 rounded-lg p-8 text-center max-w-2xl mx-auto mt-20">
        <div className="text-red-500 text-5xl mb-4">⚠️</div>
        <h2 className="text-xl font-bold text-red-100 mb-2">Error</h2>
        <p className="text-red-400 text-sm mb-6">{error}</p>
        <button
            onClick={() => window.location.reload()}
            className="bg-red-600 hover:bg-red-500 text-white px-6 py-2 rounded font-bold transition-colors"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="relative w-full h-[calc(100vh-160px)]">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Attack Surface Graph</h1>
          <p className="text-slate-400 text-sm">Interactive visualization of discovered assets and findings.</p>
        </div>
        <div className="flex space-x-4">
             <div className="flex items-center space-x-2">
                 <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
                 <span className="text-xs text-slate-400">Host</span>
             </div>
             <div className="flex items-center space-x-2">
                 <span className="w-3 h-3 rounded-full bg-cyan-500"></span>
                 <span className="text-xs text-slate-400">Endpoint</span>
             </div>
             <div className="flex items-center space-x-2">
                 <span className="w-3 h-3 rounded-full bg-red-500"></span>
                 <span className="text-xs text-slate-400">Finding</span>
             </div>
        </div>
      </div>

      <div className="w-full h-full relative">
        {data && (
          <AttackSurfaceGraph
            data={data}
            onNodeClick={(node) => setSelectedNode(node)}
          />
        )}

        <NodeDetailsPanel
          node={selectedNode}
          onClose={() => setSelectedNode(null)}
        />
      </div>
    </div>
  );
}
