'use client';

import { useParams } from 'next/navigation';
import ReconStatusBanner from './ReconStatusBanner';

export default function ReconStatusBannerContainer() {
  const params = useParams();
  const investigationId = params?.investigationId as string | undefined;

  if (!investigationId) return null;

  return <ReconStatusBanner investigationId={investigationId} />;
}
