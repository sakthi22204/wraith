import React from 'react';
import Link from 'next/link';
import { fetchPrograms } from '@/lib/graphApi';

export default async function HomePage() {
  let programs = [];
  try {
    programs = await fetchPrograms();
  } catch (e) {
    console.error('Failed to fetch programs', e);
  }

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-bold tracking-tight mb-2">Target Programs</h1>
          <p className="text-slate-400">Select a program to visualize its attack surface or monitor active scans.</p>
        </div>
        <button className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-bold transition-all shadow-lg shadow-indigo-600/20 active:scale-95 disabled:opacity-50" disabled>
          + Create Program
        </button>
      </div>

      {programs.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <div className="text-slate-500 mb-4 font-medium italic">No programs found in the knowledge graph.</div>
          <p className="text-slate-600 text-sm max-w-md mx-auto mb-6">
             Start by adding a target program via the graph_db API to begin building your attack surface model.
          </p>
          <div className="inline-block bg-slate-800 text-slate-400 font-mono text-xs p-3 rounded-lg border border-slate-700">
            curl -X POST http://localhost:8001/api/v1/programs ...
          </div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {programs.map((program: any) => (
            <div key={program.id} className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden hover:border-indigo-500/50 transition-colors group">
              <div className="p-6">
                <div className="flex justify-between items-start mb-4">
                  <div className="bg-indigo-900/30 text-indigo-400 text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded">
                    {program.platform}
                  </div>
                  <div className="text-slate-500 text-[10px] font-mono uppercase">
                    {program.id.slice(0, 8)}
                  </div>
                </div>
                <h2 className="text-xl font-bold mb-2 group-hover:text-indigo-400 transition-colors">{program.name}</h2>
                <div className="text-slate-400 text-sm mb-6 line-clamp-2">
                  Scope: {program.scope_domains?.join(', ') || 'N/A'}
                </div>
                <div className="flex space-x-3">
                  <Link
                    href={`/programs/${program.id}/graph`}
                    className="flex-1 text-center bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold py-2 rounded transition-colors"
                  >
                    View Graph
                  </Link>
                  <button
                    className="flex-1 text-center bg-slate-800 text-slate-500 text-xs font-bold py-2 rounded cursor-not-allowed"
                    disabled
                  >
                    Scans
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
