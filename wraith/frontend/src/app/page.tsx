'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { fetchPrograms, createProgram, deleteProgram } from '@/lib/graphApi';

export default function HomePage() {
  const [programs, setPrograms] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newProgram, setNewProgram] = useState({ name: '', platform: '', scope: '' });

  const loadPrograms = async () => {
    try {
      const data = await fetchPrograms();
      setPrograms(data);
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadPrograms();
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await createProgram(newProgram.name, newProgram.platform, newProgram.scope.split(',').map(s => s.trim()));
      setIsModalOpen(false);
      setNewProgram({ name: '', platform: '', scope: '' });
      loadPrograms();
    } catch (e) {
      alert('Failed to create program');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this program and all its findings?')) return;
    try {
      await deleteProgram(id);
      loadPrograms();
    } catch (e) {
      alert('Failed to delete program');
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-bold tracking-tight mb-2">Target Programs</h1>
          <p className="text-slate-400">Select a program to manage its attack surface and exploitation cycles.</p>
        </div>
        <button
          onClick={() => setIsModalOpen(true)}
          className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg font-bold transition-all shadow-lg shadow-indigo-600/20 active:scale-95"
        >
          + Create Program
        </button>
      </div>

      {isLoading ? (
        <div className="text-center py-20 text-slate-500 animate-pulse">Loading target programs...</div>
      ) : programs.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <div className="text-slate-500 mb-4 font-medium italic">No programs found in the knowledge graph.</div>
          <p className="text-slate-600 text-sm max-w-md mx-auto mb-6">
             Add a target program to begin building your attack surface model.
          </p>
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
                  <button
                    onClick={() => handleDelete(program.id)}
                    className="text-slate-600 hover:text-red-500 transition-colors"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                  </button>
                </div>
                <h2 className="text-xl font-bold mb-2 group-hover:text-indigo-400 transition-colors">{program.name}</h2>
                <div className="text-slate-400 text-sm mb-6 line-clamp-2 min-h-[40px]">
                  Scope: {program.scope_domains?.join(', ') || 'N/A'}
                </div>
                <div className="flex space-x-3">
                  <Link
                    href={`/programs/${program.id}`}
                    className="flex-1 text-center bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold py-2 rounded transition-colors"
                  >
                    Dashboard
                  </Link>
                  <Link
                    href={`/programs/${program.id}/graph`}
                    className="flex-1 text-center bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold py-2 rounded transition-colors"
                  >
                    Graph
                  </Link>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {isModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-xl font-bold">New Target Program</h3>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <form onSubmit={handleCreate} className="p-6 space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Program Name</label>
                <input
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white outline-none focus:border-indigo-500"
                  value={newProgram.name}
                  onChange={e => setNewProgram({...newProgram, name: e.target.value})}
                  placeholder="e.g. Acme Corp Bug Bounty"
                />
              </div>
              <div>
                <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Platform</label>
                <input
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white outline-none focus:border-indigo-500"
                  value={newProgram.platform}
                  onChange={e => setNewProgram({...newProgram, platform: e.target.value})}
                  placeholder="e.g. HackerOne"
                />
              </div>
              <div>
                <label className="block text-xs font-bold uppercase text-slate-500 mb-1">Scope (Comma-separated domains)</label>
                <textarea
                  required
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2 text-white outline-none focus:border-indigo-500 h-24"
                  value={newProgram.scope}
                  onChange={e => setNewProgram({...newProgram, scope: e.target.value})}
                  placeholder="example.com, api.example.com"
                />
              </div>
              <button type="submit" className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-xl transition-all shadow-lg shadow-indigo-600/20">
                Create Program
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
