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

describe('AgentActivityFeed', () => {
  it('renders initial state and appends steps', async () => {
    render(<AgentActivityFeed sessionId="test-session" />);

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
