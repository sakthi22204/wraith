import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import ScopeRules from '../src/components/ScopeRules';
import '@testing-library/jest-dom';

describe('ScopeRules', () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as any;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('renders allow and deny rules read-only', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => [
        { id: 1, investigation_id: 'inv-1', pattern: 'example.com', rule_type: 'allow' },
        { id: 2, investigation_id: 'inv-1', pattern: '*.example.com', rule_type: 'deny' }
      ]
    });

    render(<ScopeRules investigationId="inv-1" />);

    await waitFor(() => expect(screen.getByText('example.com')).toBeInTheDocument());
    expect(screen.getByText('*.example.com')).toBeInTheDocument();
    expect(screen.getByText(/Deny rules always win/i)).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining('/api/v1/roe/scope/inv-1'));
  });

  it('shows an empty state when no rules exist', async () => {
    fetchMock.mockResolvedValue({ ok: true, json: async () => [] });

    render(<ScopeRules investigationId="inv-1" />);

    await waitFor(() => expect(screen.getByText(/No explicit scope rules defined/i)).toBeInTheDocument());
  });
});
