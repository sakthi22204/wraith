'use client';

import React from 'react';
import { useParams } from 'next/navigation';
import AgentActivityFeed from '@/components/AgentActivityFeed';

export default function AgentFeedPage() {
  const params = useParams();
  const investigationId = params?.investigationId as string;
  const sessionId = params?.sessionId as string;

  return (
    <div className="flex flex-col h-[calc(100vh-140px)]">
      <div className="mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Agent Reasoning Session</h1>
          <p className="text-slate-400 text-sm font-mono uppercase tracking-widest mt-1">
             ID: {sessionId}
          </p>
        </div>
        <div className="bg-slate-900 border border-slate-800 px-4 py-2 rounded-lg flex items-center space-x-3">
             <div className="text-[10px] font-bold text-slate-500 uppercase tracking-wider">Investigation</div>
             <div className="text-sm font-bold text-slate-300">{investigationId?.slice(0, 8)}...</div>
        </div>
      </div>

      <div className="flex-1 min-h-0 max-w-4xl mx-auto w-full">
        <AgentActivityFeed sessionId={sessionId} />
      </div>
    </div>
  );
}
