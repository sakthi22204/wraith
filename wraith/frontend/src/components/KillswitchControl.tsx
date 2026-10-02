'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { fetchKillswitchStatus, setKillswitch } from '@/lib/exploitApi';
import { errorMessage } from '@/lib/apiError';

type KillswitchState = 'loading' | 'active' | 'inactive' | 'error';
type PendingAction = 'activate' | 'deactivate' | null;

export default function KillswitchControl() {
  const [state, setState] = useState<KillswitchState>('loading');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isBusy, setIsBusy] = useState(false);
  const [confirming, setConfirming] = useState<PendingAction>(null);
  const [lastError, setLastError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await fetchKillswitchStatus();
      setState(data.active === true ? 'active' : 'inactive');
      setLastError(null);
    } catch (e) {
      setState('error');
      setLastError(errorMessage(e, 'Unable to reach the exploit runner service.'));
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [refresh]);

  const handleConfirm = async () => {
    if (!confirming) return;
    setIsBusy(true);
    setLastError(null);
    try {
      await setKillswitch(confirming);
      setState(confirming === 'activate' ? 'active' : 'inactive');
      setConfirming(null);
      setIsModalOpen(false);
      toast.success(confirming === 'activate' ? 'Killswitch activated' : 'Killswitch deactivated');
      refresh();
    } catch (e) {
      toast.error(errorMessage(e, `Failed to ${confirming} killswitch`));
      await refresh();
      setLastError('Backend reported an error. The killswitch state was not changed.');
    } finally {
      setIsBusy(false);
    }
  };

  const badgeClass =
    state === 'active'
      ? 'bg-red-600 text-white border-red-400 animate-pulse'
      : state === 'error'
      ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
      : 'bg-slate-800 text-slate-400 border-slate-700';

  const badgeDot =
    state === 'active'
      ? 'bg-white'
      : state === 'error'
      ? 'bg-amber-400'
      : 'bg-emerald-400';

  const label =
    state === 'loading'
      ? 'Checking…'
      : state === 'active'
      ? 'KILLSWITCH ACTIVE'
      : state === 'error'
      ? 'KILLSWITCH UNKNOWN'
      : 'KILLSWITCH INACTIVE';

  const currentActive = state === 'active';

  return (
    <>
      <button
        onClick={() => setIsModalOpen(true)}
        title="Global killswitch control"
        className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest border transition-all active:scale-95 ${badgeClass}`}
      >
        <span className={`w-2 h-2 rounded-full ${badgeDot}`}></span>
        <span>{label}</span>
      </button>

      {isModalOpen && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-md flex items-center justify-center z-[150] p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md overflow-hidden shadow-2xl">
            <div className="p-6 border-b border-slate-800 flex justify-between items-center">
              <h3 className="text-xl font-bold font-heading">Global Killswitch</h3>
              <button onClick={() => { setIsModalOpen(false); setConfirming(null); }} className="text-slate-400 hover:text-white">&times;</button>
            </div>

            <div className="p-6 space-y-6">
              <div className={`rounded-xl p-4 border flex items-center space-x-3 ${
                currentActive
                  ? 'bg-red-950/30 border-red-900/40'
                  : state === 'error'
                  ? 'bg-amber-950/20 border-amber-900/40'
                  : 'bg-slate-950 border-slate-800'
              }`}>
                <span className={`w-3 h-3 rounded-full ${currentActive ? 'bg-red-500 animate-ping' : state === 'error' ? 'bg-amber-400' : 'bg-emerald-500'}`}></span>
                <div>
                  <div className="text-sm font-bold text-slate-100">
                    {state === 'loading' ? 'Checking status…' : currentActive ? 'KILLSWITCH IS ACTIVE' : state === 'error' ? 'STATUS UNKNOWN' : 'KILLSWITCH IS INACTIVE'}
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {currentActive
                      ? 'All autonomous exploitation and tool execution is halted.'
                      : 'Exploitation and tool execution are permitted subject to scope and rate limits.'}
                  </p>
                </div>
              </div>

              {lastError && (
                <div className="bg-red-950/40 border border-red-900/50 rounded-xl p-3 text-xs text-red-200">
                  {lastError}
                  <button onClick={refresh} className="ml-2 underline hover:text-white">Retry</button>
                </div>
              )}

              {state === 'error' && (
                <button
                  onClick={refresh}
                  disabled={isBusy}
                  className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-3 rounded-xl text-sm transition-all active:scale-95 disabled:opacity-50"
                >
                  Retry Status Check
                </button>
              )}

              {state !== 'error' && !confirming && (
                <button
                  onClick={() => setConfirming(currentActive ? 'deactivate' : 'activate')}
                  disabled={isBusy || state === 'loading'}
                  className={`w-full font-bold py-3 rounded-xl text-sm transition-all active:scale-95 disabled:opacity-50 ${
                    currentActive
                      ? 'bg-slate-800 hover:bg-slate-700 text-white border border-slate-700'
                      : 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-900/30'
                  }`}
                >
                  {currentActive ? 'Deactivate Killswitch' : 'Activate Killswitch'}
                </button>
              )}

              {confirming && (
                <div className="space-y-4 border-t border-slate-800 pt-4">
                  <p className="text-sm text-slate-300">
                    {confirming === 'activate'
                      ? 'Activating the killswitch immediately halts all exploitation and tool execution across every investigation. This is logged in the immutable audit trail.'
                      : 'Deactivating the killswitch resumes normal exploitation and tool execution.'}
                  </p>
                  <div className="flex space-x-3">
                    <button
                      onClick={() => setConfirming(null)}
                      disabled={isBusy}
                      className="flex-1 bg-slate-800 text-white font-bold py-3 rounded-xl text-sm active:scale-95 transition-all disabled:opacity-50"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleConfirm}
                      disabled={isBusy}
                      className={`flex-[2] text-white font-bold py-3 rounded-xl text-sm uppercase tracking-widest active:scale-95 transition-all disabled:opacity-50 ${
                        confirming === 'activate'
                          ? 'bg-red-600 hover:bg-red-500 shadow-lg shadow-red-900/30'
                          : 'bg-emerald-600 hover:bg-emerald-500'
                      }`}
                    >
                      {isBusy ? 'Working…' : `Yes, ${confirming === 'activate' ? 'Activate' : 'Deactivate'}`}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
