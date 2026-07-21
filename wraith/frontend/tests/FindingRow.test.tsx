import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import FindingRow from '../src/components/FindingRow';
import { Finding } from '../src/types/graph';
import '@testing-library/jest-dom';

const mockFindingFull: Finding = {
  id: 'finding-1',
  vuln_type: 'sqli',
  severity: 'critical',
  confidence: 'high',
  status: 'HUMAN_CONFIRMED',
  description: 'SQL Injection on endpoint',
  discovered_at: '2023-01-01T12:00:00Z',
  ai_confidence: 0.95,
  ai_reasoning: 'AI confirmed injection vulnerability',
  corroborating_sources: ['sqlmap'],
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  evidence: 'SELECT * FROM users'
};

const mockFindingNullConfidence: Finding = {
  ...mockFindingFull,
  id: 'finding-2',
  ai_confidence: null
};

describe('FindingRow', () => {
  it('renders all fields for a full fixture finding', () => {
    const handleClick = jest.fn();
    render(
      <table>
        <tbody>
          <FindingRow
            finding={mockFindingFull}
            affectedAsset="Endpoint: [GET] /api/users"
            sourceTool="sqlmap"
            onClick={handleClick}
          />
        </tbody>
      </table>
    );

    expect(screen.getByText(/critical/i)).toBeInTheDocument();
    expect(screen.getByText(/sqli/i)).toBeInTheDocument();
    expect(screen.getByText(/HUMAN_CONFIRMED/)).toBeInTheDocument();
    expect(screen.getByText('95%')).toBeInTheDocument();
    expect(screen.getByText('Endpoint: [GET] /api/users')).toBeInTheDocument();
    expect(screen.getByText('sqlmap')).toBeInTheDocument();
  });

  it('renders "N/A" gracefully when ai_confidence is null', () => {
    render(
      <table>
        <tbody>
          <FindingRow
            finding={mockFindingNullConfidence}
            affectedAsset="Endpoint: [GET] /api/users"
            sourceTool="sqlmap"
            onClick={() => {}}
          />
        </tbody>
      </table>
    );

    expect(screen.getByText('N/A')).toBeInTheDocument();
  });

  it('clicking calls the expected handler', () => {
    const handleClick = jest.fn();
    render(
      <table>
        <tbody>
          <FindingRow
            finding={mockFindingFull}
            affectedAsset="Endpoint: [GET] /api/users"
            sourceTool="sqlmap"
            onClick={handleClick}
          />
        </tbody>
      </table>
    );

    fireEvent.click(screen.getByText('SQLI'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });
});
