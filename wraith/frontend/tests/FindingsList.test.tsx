import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import FindingsList from '../src/components/FindingsList';
import { Finding, GraphResponse } from '../src/types/graph';
import '@testing-library/jest-dom';

const mockFindings: Finding[] = [
  {
    id: 'finding-1',
    vuln_type: 'sqli',
    severity: 'critical',
    confidence: 'high',
    status: 'HUMAN_CONFIRMED',
    description: 'SQL Injection in input',
    discovered_at: '2023-01-01T12:00:00Z',
    ai_confidence: 0.9
  },
  {
    id: 'finding-2',
    vuln_type: 'xss',
    severity: 'medium',
    confidence: 'medium',
    status: 'AI_VALIDATED',
    description: 'Reflected XSS in search',
    discovered_at: '2023-01-02T12:00:00Z',
    ai_confidence: 0.7
  },
  {
    id: 'finding-3',
    vuln_type: 'idor',
    severity: 'high',
    confidence: 'high',
    status: 'DUPLICATE',
    description: 'IDOR in profile',
    discovered_at: '2023-01-03T12:00:00Z',
    ai_confidence: 0.8
  },
  {
    id: 'finding-4',
    vuln_type: 'ssrf',
    severity: 'high',
    confidence: 'low',
    status: 'FALSE_POSITIVE',
    description: 'SSRF false alarm',
    discovered_at: '2023-01-04T12:00:00Z',
    ai_confidence: 0.2
  }
];

const mockGraph: GraphResponse = {
  nodes: [
    { id: 'endpoint-1', labels: ['Endpoint'], properties: { url: '/api/v1/query', method: 'POST' } },
    { id: 'endpoint-2', labels: ['Endpoint'], properties: { url: '/search', method: 'GET' } },
    { id: 'finding-1', labels: ['Finding'], properties: {} },
    { id: 'finding-2', labels: ['Finding'], properties: {} },
    { id: 'finding-3', labels: ['Finding'], properties: {} },
    { id: 'finding-4', labels: ['Finding'], properties: {} }
  ],
  links: [
    { source: 'endpoint-1', target: 'finding-1', type: 'HAS_FINDING' },
    { source: 'endpoint-2', target: 'finding-2', type: 'HAS_FINDING' }
  ]
};

describe('FindingsList', () => {
  it('renders fixture findings and default view excludes DUPLICATE/FALSE_POSITIVE', () => {
    render(<FindingsList findings={mockFindings} graph={mockGraph} />);

    // Should render SQLI and XSS
    expect(screen.getByText('Endpoint: [POST] /api/v1/query')).toBeInTheDocument();
    expect(screen.getByText('Endpoint: [GET] /search')).toBeInTheDocument();

    // Should NOT render IDOR or SSRF by default (as they are DUPLICATE and FALSE_POSITIVE)
    expect(screen.queryByText('Parameter: id (query) on /profile')).not.toBeInTheDocument();
    expect(screen.queryByText('Endpoint: [GET] /ssrf')).not.toBeInTheDocument();
  });

  it('toggle reveals DUPLICATE and FALSE_POSITIVE', () => {
    // Modify graph with the relevant nodes so they map correctly when shown
    const expandedGraph = {
      nodes: [
        ...mockGraph.nodes,
        { id: 'endpoint-3', labels: ['Endpoint'], properties: { url: '/profile', method: 'GET' } },
        { id: 'param-1', labels: ['Parameter'], properties: { name: 'id', location: 'query' } },
        { id: 'endpoint-4', labels: ['Endpoint'], properties: { url: '/ssrf', method: 'GET' } }
      ],
      links: [
        ...mockGraph.links,
        { source: 'endpoint-3', target: 'param-1', type: 'HAS_PARAMETER' },
        { source: 'param-1', target: 'finding-3', type: 'HAS_FINDING' },
        { source: 'endpoint-4', target: 'finding-4', type: 'HAS_FINDING' }
      ]
    };

    render(<FindingsList findings={mockFindings} graph={expandedGraph} />);

    // Verify checkbox is there and check it
    const toggle = screen.getByLabelText(/Show duplicates & false positives/i);
    fireEvent.click(toggle);

    // Now they should be visible
    expect(screen.getByText(/Parameter: id/)).toBeInTheDocument();
    expect(screen.getByText('Endpoint: [GET] /ssrf')).toBeInTheDocument();
  });

  it('each filter dimension narrows the list correctly', () => {
    render(<FindingsList findings={mockFindings} graph={mockGraph} />);

    // Filter by Severity: CRITICAL
    const critBtn = screen.getByRole('button', { name: 'critical' });
    fireEvent.click(critBtn);

    // Only SQLI (Critical) should be visible, XSS (Medium) should be hidden
    expect(screen.getByText('Endpoint: [POST] /api/v1/query')).toBeInTheDocument();
    expect(screen.queryByText('Endpoint: [GET] /search')).not.toBeInTheDocument();

    // Clear Severity: CRITICAL
    fireEvent.click(critBtn);
    expect(screen.getByText('Endpoint: [GET] /search')).toBeInTheDocument();

    // Filter by Status: AI_VALIDATED
    const aiValBtn = screen.getByRole('button', { name: 'AI VALIDATED' });
    fireEvent.click(aiValBtn);

    // Only XSS should be visible
    expect(screen.queryByText('Endpoint: [POST] /api/v1/query')).not.toBeInTheDocument();
    expect(screen.getByText('Endpoint: [GET] /search')).toBeInTheDocument();
  });

  it('text search filters list correctly', () => {
    render(<FindingsList findings={mockFindings} graph={mockGraph} />);

    const searchInput = screen.getByPlaceholderText('Search vuln type, description...');
    fireEvent.change(searchInput, { target: { value: 'reflected' } });

    // Only XSS description contains 'Reflected'
    expect(screen.queryByText('Endpoint: [POST] /api/v1/query')).not.toBeInTheDocument();
    expect(screen.getByText('Endpoint: [GET] /search')).toBeInTheDocument();
  });

  it('renders empty state correctly when list is empty', () => {
    render(<FindingsList findings={[]} graph={{ nodes: [], links: [] }} />);

    expect(
      screen.getByText(/No findings yet — start a recon session or agent session/i)
    ).toBeInTheDocument();
  });
});
