'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { toast } from 'sonner';
import { fetchPrograms, createProgram, deleteProgram } from '@/lib/graphApi';
import Skeleton from '@/components/Skeleton';
import { Program } from '@/types/graph';

export default function HomePage() {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [programToDelete, setProgramToDelete] = useState<Program | null>(null);
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
      toast.success('Program created successfully');
      loadPrograms();
    } catch (e) {
      toast.error('Failed to create program');
    }
  };

  const handleDelete = async () => {
    if (!programToDelete) return;
    try {
      await deleteProgram(programToDelete.id);
      toast.success('Program deleted successfully');
      setIsDeleteModalOpen(false);
      setProgramToDelete(null);
      loadPrograms();
    } catch (e) {
      toast.error('Failed to delete program');
    }
  };

  return (
    <div className="space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-bold tracking-tight mb-2 font-heading">Target Programs</h1>
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
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {[1, 2, 3, 4, 5, 6].map(i => (
            <div key={i} className="bg-slate-900/40 border border-slate-800 rounded-xl p-6 space-y-4">
              <div className="flex justify-between items-start">
                <Skeleton className="h-4 w-16" />
                <Skeleton className="h-4 w-4" />
              </div>
              <Skeleton className="h-6 w-3/4" />
              <Skeleton className="h-4 w-full" />
              <div className="flex space-x-3 pt-2">
                <Skeleton className="h-8 flex-1" />
                <Skeleton className="h-8 flex-1" />
              </div>
            </div>
          ))}
        </div>
      ) : programs.length === 0 ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
          <div className="text-slate-500 mb-4 font-medium italic">No programs found in the knowledge graph.</div>
          <p className="text-slate-600 text-sm max-w-md mx-auto mb-6">
             Add a target program to begin building your attack surface model.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {programs.map((program: Program) => (
            <div key={program.id} className="bg-gradient-to-br from-slate-900/60 to-slate-950/90 backdrop-blur-md border border-indigo-500/35 rounded-xl overflow-hidden hover:border-indigo-500/60 transition-all group shadow-lg shadow-indigo-500/12 hover:shadow-indigo-500/20">
              <div className="p-6 relative">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center space-x-2">
                    <div className="bg-indigo-900/30 text-indigo-400 text-[10px] font-bold uppercase tracking-widest px-2 py-1 rounded">
                      {program.platform}
                    </div>
                    <div className="flex items-center">
                      <div className="w-2 h-2 bg-emerald-500 rounded-full shadow-[0_0_8px_rgba(16,185,129,0.6)] animate-pulse"></div>
                    </div>
                  </div>
                  <button
                    onClick={() => {
                      setProgramToDelete(program);
                      setIsDeleteModalOpen(true);
                    }}
                    className="text-slate-600 hover:text-red-500 transition-colors"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
                  </button>
                </div>
                <h2 className="text-xl font-bold mb-2 group-hover:text-indigo-400 transition-colors font-heading">{program.name}</h2>
                <div className="text-slate-400 text-sm mb-6 line-clamp-2 min-h-[40px]">
                  Scope: {program.scope_domains?.join(', ') || 'N/A'}
                </div>

                <div className="flex justify-between items-center mb-6">
                  <div className="font-mono text-[10px] text-slate-500 truncate max-w-[120px]" title={program.id}>
                    {program.id}
                  </div>
                  {/* Finding summary would go here if we had the count */}
                  <div className="flex space-x-1">
                    <span className="bg-slate-950 border border-slate-800 text-[10px] font-bold px-2 py-0.5 rounded text-slate-400 uppercase">
                      Ready
                    </span>
                  </div>
                </div>

                <div className="flex space-x-3">
                  <Link
                    href={`/programs/${program.id}`}
                    className="flex-1 text-center bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold py-2 rounded transition-all active:scale-95"
                  >
                    Dashboard
                  </Link>
                  <Link
                    href={`/programs/${program.id}/graph`}
                    className="flex-1 text-center bg-slate-800 hover:bg-slate-700 text-white text-xs font-bold py-2 rounded transition-all active:scale-95"
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
              <h3 className="text-xl font-bold font-heading">New Target Program</h3>
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
              <button type="submit" className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-3 rounded-xl transition-all shadow-lg shadow-indigo-600/20 active:scale-95">
                Create Program
              </button>
            </form>
          </div>
        </div>
      )}

      {isDeleteModalOpen && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-xl font-bold text-red-500 font-heading">Confirm Deletion</h3>
              <button onClick={() => setIsDeleteModalOpen(false)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-slate-300">
                Are you sure you want to delete <span className="font-bold text-white">{programToDelete?.name}</span>?
                This will remove all associated findings and graph data. This action cannot be undone.
              </p>
              <div className="flex space-x-3">
                <button
                  onClick={() => setIsDeleteModalOpen(false)}
                  className="flex-1 bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl transition-all active:scale-95"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDelete}
                  className="flex-1 bg-red-600 hover:bg-red-500 text-white font-bold py-3 rounded-xl transition-all shadow-lg shadow-red-600/20 active:scale-95"
                >
                  Delete
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
