'use client';

import React, { useState, useEffect } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { toast } from 'sonner';
import { Finding } from '@/types/graph';
import { fetchReviewQueue, reviewFinding } from '@/lib/graphApi';
import SeverityBadge from '@/components/SeverityBadge';
import Skeleton from '@/components/Skeleton';

export default function ReviewQueuePage() {
  const { investigationId } = useParams();
  const [queue, setQueue] = useState<Finding[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [note, setNote] = useState('');

  const loadQueue = async () => {
    try {
      const data = await fetchReviewQueue(investigationId as string);
      setQueue(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadQueue();
  }, [investigationId]);

  // A review can only refute a finding. Confirmation in this system comes from
  // executed evidence or independent corroboration, neither of which a reviewer
  // can assert here, so there is deliberately no "confirm" action.
  const handleReview = async (decision: 'false_positive') => {
    if (!selectedFinding) return;
    try {
      await reviewFinding(selectedFinding.id, decision, note);
      setSelectedFinding(null);
      setNote('');
      toast.success('Review submitted successfully');
      loadQueue();
    } catch (e) {
      toast.error('Failed to submit review');
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-start">
        <div>
          <Link href={`/investigations/${investigationId}`} className="text-indigo-400 text-sm font-bold hover:underline mb-2 inline-block">← Back to Dashboard</Link>
          <h1 className="text-4xl font-bold tracking-tight">Review Queue</h1>
          <p className="text-slate-400">Refute low-confidence findings for investigation: <span className="font-mono">{investigationId}</span></p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 h-[calc(100vh-250px)]">
        <div className="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden flex flex-col">
           <div className="p-4 border-b border-slate-800 bg-slate-900/50 font-bold text-sm uppercase tracking-wider text-slate-500">
              Findings Needing Review
           </div>
           <div className="flex-1 overflow-y-auto divide-y divide-slate-800">
             {isLoading ? (
               <div className="p-4 space-y-4">
                 {[1, 2, 3, 4, 5].map(i => (
                    <div key={i} className="space-y-2">
                       <div className="flex justify-between">
                         <Skeleton className="h-4 w-12" />
                         <Skeleton className="h-3 w-8" />
                       </div>
                       <Skeleton className="h-4 w-3/4" />
                       <Skeleton className="h-3 w-full" />
                    </div>
                 ))}
               </div>
             ) : queue.length === 0 ? (
               <div className="p-10 text-center text-slate-600 italic">Queue is empty! All findings verified.</div>
             ) : (
               queue.map(f => (
                 <button
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`w-full p-4 text-left hover:bg-indigo-600/10 transition-colors ${selectedFinding?.id === f.id ? 'bg-indigo-600/20 border-l-4 border-indigo-500' : ''}`}
                 >
                   <div className="flex justify-between items-start mb-1">
                     <SeverityBadge severity={f.severity} />
                     <span className="text-[10px] font-mono text-slate-500">{(f.ai_confidence ?? 0 * 100).toFixed(0)}% Conf</span>
                   </div>
                   <div className="font-bold text-sm text-slate-200">{f.vuln_type.toUpperCase()}</div>
                   <div className="text-xs text-slate-500 truncate mt-1">{f.description}</div>
                 </button>
               ))
             )}
           </div>
        </div>

        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-2xl flex flex-col overflow-hidden">
          {selectedFinding ? (
            <>
              <div className="p-6 border-b border-slate-800 bg-slate-900/50">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-2xl font-bold">{selectedFinding.vuln_type.toUpperCase()}</h2>
                  <SeverityBadge severity={selectedFinding.severity} />
                </div>
                <div className="space-y-4">
                   <div>
                     <label className="text-xs font-bold text-slate-500 uppercase block mb-1">Description</label>
                     <p className="text-slate-300 text-sm leading-relaxed">{selectedFinding.description}</p>
                   </div>
                   <div className="grid grid-cols-2 gap-4">
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                        <label className="text-[10px] font-bold text-slate-600 uppercase block mb-1">AI Confidence</label>
                        <span className="text-lg font-bold text-indigo-400">{(selectedFinding.ai_confidence ?? 0 * 100).toFixed(1)}%</span>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                        <label className="text-[10px] font-bold text-slate-600 uppercase block mb-1">Status</label>
                        <span className="text-lg font-bold text-slate-400 uppercase">{selectedFinding.status}</span>
                      </div>
                   </div>
                   {selectedFinding.ai_reasoning && (
                     <div className="bg-indigo-900/10 border border-indigo-500/20 rounded-lg p-4 italic text-sm text-indigo-200/70">
                       <span className="font-bold not-italic text-indigo-400 block mb-1 text-xs uppercase">AI Reasoning:</span>
                       "{selectedFinding.ai_reasoning}"
                     </div>
                   )}
                </div>
              </div>
              <div className="flex-1 p-6 space-y-4 bg-slate-950/30 overflow-y-auto">
                <div>
                   <label className="text-xs font-bold text-slate-500 uppercase block mb-2">Reviewer Notes</label>
                   <textarea
                    value={note}
                    onChange={e => setNote(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl p-4 text-white text-sm outline-none focus:border-indigo-500 h-32"
                    placeholder="Enter justification for your decision..."
                   />
                </div>
              </div>
              <div className="p-6 bg-slate-900 border-t border-slate-800 flex space-x-4">
                <button
                  onClick={() => handleReview('false_positive')}
                  className="flex-1 bg-red-600 hover:bg-red-500 text-white font-bold py-3 rounded-xl transition-colors shadow-lg shadow-red-900/20"
                >
                  Mark False Positive
                </button>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-slate-600 italic">
              Select a finding from the list to review details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
