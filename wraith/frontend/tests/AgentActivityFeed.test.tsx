import React from 'react';
import { render, screen, act } from '@testing-library/react';
import AgentActivityFeed from '../src/components/AgentActivityFeed';
import '@testing-library/jest-dom';

// Mock EventSource
let mockEventSourceInstance: any;

class MockEventSource {
  onmessage: ((ev: any) => void) | null = null;
  onerror: ((ev: any) => void) | null = null;
  addEventListener = jest.fn();
  close = jest.fn();
  constructor() {
    mockEventSourceInstance = this;
  }
}

global.EventSource = MockEventSource as any;

// Mock global fetch
global.fetch = jest.fn().mockImplementation(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({ status: 'running', reasoning_log: [] }),
  })
) as any;

describe('AgentActivityFeed', () => {
  it('renders initial state and appends steps', async () => {
    render(<AgentActivityFeed sessionId="test-session" />);

    // Wait for the async initFeed fetch to resolve and instantiate MockEventSource
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });

    expect(screen.getByText(/Waiting for agent/i)).toBeInTheDocument();

    // Simulate a message
    const mockStep = {
      reason: {
        reasoning_log: ['Thinking about things...']
      }
    };

    await act(async () => {
      mockEventSourceInstance.onmessage({
        data: JSON.stringify(mockStep)
      });
    });

    expect(screen.getByText('Thinking about things...')).toBeInTheDocument();
  });
});
