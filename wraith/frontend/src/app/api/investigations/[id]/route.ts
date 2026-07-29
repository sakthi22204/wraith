import { NextResponse } from 'next/server';

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const adminToken = process.env.ADMIN_API_TOKEN;
  const graphDbUrl = process.env.GRAPH_DB_URL || 'http://graph_api:8001';
  const baseUrl = graphDbUrl.endsWith('/api/v1') ? graphDbUrl : `${graphDbUrl}/api/v1`;

  try {
    const response = await fetch(`${baseUrl}/investigations/${id}?confirm=true`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    if (!response.ok) {
      const error = await response.text();
      return NextResponse.json({ error }, { status: response.status });
    }

    return NextResponse.json({ status: 'success' });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
