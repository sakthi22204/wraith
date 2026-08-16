import React from 'react';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import KillswitchControl from '../src/components/KillswitchControl';
import '@testing-library/jest-dom';

describe('KillswitchControl', () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as any;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('shows inactive state when backend reports active=false', async () => {
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ active: false }) });

    render(<KillswitchControl />);

    await waitFor(() => expect(screen.getByText(/KILLSWITCH INACTIVE/i)).toBeInTheDocument());
  });

  it('shows active state when backend reports active=true', async () => {
    fetchMock.mockResolvedValue({ ok: true, json: async () => ({ active: true }) });

    render(<KillswitchControl />);

    await waitFor(() => expect(screen.getByText(/KILLSWITCH ACTIVE/i)).toBeInTheDocument());
  });

  it('activates the killswitch via the server proxy after confirmation', async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => ({ active: false }) })    // initial status
      .mockResolvedValueOnce({ ok: true, json: async () => ({ status: 'Killswitch activated' }) }) // POST
      .mockResolvedValueOnce({ ok: true, json: async () => ({ active: true }) });     // refresh

    render(<KillswitchControl />);

    await waitFor(() => expect(screen.getByText(/KILLSWITCH INACTIVE/i)).toBeInTheDocument());

    fireEvent.click(screen.getByText(/KILLSWITCH INACTIVE/i));
    fireEvent.click(screen.getByText(/Activate Killswitch/i));
    fireEvent.click(screen.getByText(/Yes, Activate/i));

    await waitFor(() => expect(screen.getByText(/KILLSWITCH ACTIVE/i)).toBeInTheDocument());

    const postCall = fetchMock.mock.calls.find(([url, init]) => init?.method === 'POST');
    expect(postCall).toBeDefined();
    expect(postCall![0]).toBe('/api/killswitch');
    expect(JSON.parse(postCall![1].body)).toEqual({ action: 'activate' });
  });

  it('surfaces errors instead of assuming success', async () => {
    fetchMock
      .mockResolvedValueOnce({ ok: true, json: async () => ({ active: false }) })
      .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ error: 'Invalid token' }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ active: false }) });

    render(<KillswitchControl />);

    await waitFor(() => expect(screen.getByText(/KILLSWITCH INACTIVE/i)).toBeInTheDocument());

    fireEvent.click(screen.getByText(/KILLSWITCH INACTIVE/i));
    fireEvent.click(screen.getByText(/Activate Killswitch/i));
    fireEvent.click(screen.getByText(/Yes, Activate/i));

    await waitFor(() => expect(screen.getByText(/Backend reported an error/i)).toBeInTheDocument());
    expect(screen.getByText(/KILLSWITCH INACTIVE/i)).toBeInTheDocument();
  });
});
