'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { fetchFindings, fetchGraph } from '@/lib/graphApi';
import { Finding, GraphResponse } from '@/types/graph';
import FindingsList from '@/components/FindingsList';
import Skeleton from '@/components/Skeleton';

export default function FindingsPage() {
  const { investigationId } = useParams();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      if (!investigationId) return;
      try {
        setIsLoading(true);
        setError(null);

        // Fetch findings list and full attack surface graph in parallel
        const [findingsData, graphData] = await Promise.all([
          fetchFindings(investigationId as string),
          fetchGraph(investigationId as string),
        ]);

        setFindings(findingsData);
        setGraph(graphData);
      } catch (err: any) {
        console.error('Error fetching findings page data:', err);
        setError('Failed to load findings data. Please verify the backend graph Foundation service is active.');
      } finally {
        setIsLoading(false);
      }
    }

    loadData();
  }, [investigationId]);

  return (
    <div className="space-y-8 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Back to dashboard header */}
      <div>
        <Link
          href={`/investigations/${investigationId}`}
          className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block font-sans"
        >
          ← Back to Dashboard
        </Link>
        <h1 className="text-4xl font-bold tracking-tight font-heading text-white">
          Investigation Findings
        </h1>
        <p className="text-slate-400 font-mono text-xs mt-1">Investigation ID: {investigationId}</p>
      </div>

      {isLoading ? (
        <div className="space-y-6">
          <Skeleton className="h-40 w-full rounded-2xl" />
          <Skeleton className="h-96 w-full rounded-2xl" />
        </div>
      ) : error ? (
        <div className="p-6 bg-red-950/40 border border-red-900/50 rounded-2xl text-center text-red-200">
          <p className="font-bold">{error}</p>
        </div>
      ) : graph ? (
        <FindingsList findings={findings} graph={graph} />
      ) : (
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-2xl text-center text-slate-400">
          <p className="italic">Data structure error: No graph topology available.</p>
        </div>
      )}
    </div>
  );
}
