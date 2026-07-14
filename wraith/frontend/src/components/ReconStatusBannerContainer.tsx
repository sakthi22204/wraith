'use client';

import { useParams } from 'next/navigation';
import ReconStatusBanner from './ReconStatusBanner';

export default function ReconStatusBannerContainer() {
  const params = useParams();
  const programId = params?.programId as string | undefined;

  if (!programId) return null;

  return <ReconStatusBanner programId={programId} />;
}
