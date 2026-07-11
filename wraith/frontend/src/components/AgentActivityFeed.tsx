'use client';

import React, { useState, useEffect, useRef } from 'react';
import { AgentStep } from '@/types/graph';
import { subscribeToAgentStream } from '../lib/agentApi';
import AgentStepCard from './AgentStepCard';

interface AgentActivityFeedProps {
  sessionId: string;
}

export default function AgentActivityFeed({ sessionId }: AgentActivityFeedProps) {
  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [status, setStatus] = useState<'connecting' | 'connected' | 'reconnecting' | 'completed' | 'error'>('connecting');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let unsubscribe: (() => void) | null = null;

    const connect = () => {
      unsubscribe = subscribeToAgentStream(
        sessionId,
        (data) => {
          setSteps((prev) => [...prev, data]);
          setStatus('connected');
        },
        (error) => {
          console.error('SSE Error:', error);
          setStatus('reconnecting');
          // EventSource will automatically retry, but we'll manually re-trigger
          // our UI state if it stays in error too long
        },
        () => {
          setStatus('completed');
        }
      );
    };

    connect();

    return () => {
      if (unsubscribe) unsubscribe();
    };
  }, [sessionId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [steps]);

  return (
    <div className="flex flex-col h-full bg-slate-900 border border-slate-700 rounded-lg overflow-hidden">
      <div className="flex justify-between items-center p-4 bg-slate-800 border-b border-slate-700">
        <h2 className="text-lg font-bold text-slate-100 flex items-center">
          Agent Activity Feed
          {status === 'connected' && (
            <span className="ml-3 flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          )}
        </h2>
        <div className="text-xs uppercase tracking-widest font-semibold">
          {status === 'connecting' && <span className="text-blue-400 animate-pulse">Connecting...</span>}
          {status === 'connected' && <span className="text-emerald-400">Live</span>}
          {status === 'reconnecting' && <span className="text-amber-400 animate-pulse">Reconnecting...</span>}
          {status === 'completed' && <span className="text-slate-400">Session Completed</span>}
          {status === 'error' && <span className="text-red-400">Connection Failed</span>}
        </div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-2 scroll-smooth"
      >
        {steps.length === 0 && status !== 'completed' && (
          <div className="h-full flex items-center justify-center text-slate-500 italic">
            Waiting for agent reasoning steps...
          </div>
        )}

        {steps.map((step, i) => (
          <AgentStepCard key={i} step={step} />
        ))}

        {status === 'completed' && (
            <div className="text-center py-8 border-t border-slate-800 mt-8">
                <div className="text-slate-500 text-sm font-bold uppercase tracking-widest mb-1">End of Session</div>
                <div className="text-slate-600 text-xs italic">The autonomous agent has finished its task.</div>
            </div>
        )}
      </div>
    </div>
  );
}
