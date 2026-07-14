'use client';

import { useEffect, useState, useRef } from 'react';
import { listReconSessions, ReconSession } from '@/lib/reconApi';
import { toast } from 'sonner';
import Link from 'next/link';

interface ReconStatusBannerProps {
  programId: string;
}

export default function ReconStatusBanner({ programId }: ReconStatusBannerProps) {
  const [activeSessions, setActiveSessions] = useState<ReconSession[]>([]);
  const lastStatuses = useRef<Record<string, string>>({});

  useEffect(() => {
    let interval: NodeJS.Timeout;

    const checkSessions = async () => {
      try {
        const sessions = await listReconSessions(programId);
        const running = sessions.filter(s => s.status === 'running' || s.status === 'accepted');

        // Check for transitions
        sessions.forEach(session => {
            const lastStatus = lastStatuses.current[session.id];
            if (lastStatus && lastStatus !== session.status && (lastStatus === 'running' || lastStatus === 'accepted')) {
                if (session.status === 'completed') {
                    toast.success(`Recon completed for ${session.domains.join(', ')}`);
                } else if (session.status === 'partial') {
                    toast.warning(`Recon partially completed for ${session.domains.join(', ')}`);
                } else if (session.status === 'failed') {
                    toast.error(`Recon failed for ${session.domains.join(', ')}`);
                }
            }
            lastStatuses.current[session.id] = session.status;
        });

        setActiveSessions(running);
      } catch (err) {
        console.error('Failed to poll recon sessions:', err);
      }
    };

    checkSessions();
    interval = setInterval(checkSessions, 10000);

    return () => clearInterval(interval);
  }, [programId]);

  if (activeSessions.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-40">
      <Link href={`/programs/${programId}/recon-sessions`}>
        <div className="bg-indigo-600/90 backdrop-blur-sm hover:bg-indigo-500 text-white px-4 py-3 rounded-2xl shadow-xl shadow-indigo-500/20 flex items-center space-x-3 cursor-pointer transition-all border border-indigo-400/30 group">
          <div className="w-2 h-2 bg-white rounded-full animate-pulse shadow-[0_0_8px_rgba(255,255,255,0.8)]" />
          <div className="text-sm font-bold tracking-tight">
            Recon running for {activeSessions[0].domains[0]}
            {activeSessions.length > 1 && ` (+${activeSessions.length - 1} more)`}
          </div>
          <div className="bg-white/20 px-2 py-0.5 rounded-md text-[10px] uppercase font-black tracking-widest group-hover:bg-white/30 transition-colors">
            View Details
          </div>
        </div>
      </Link>
    </div>
  );
}
