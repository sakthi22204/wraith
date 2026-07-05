import React from 'react';
import { render, screen } from '@testing-library/react';
import AttackSurfaceGraph from '../src/components/AttackSurfaceGraph';
import '@testing-library/jest-dom';

// Mock react-force-graph-2d since it requires a canvas/DOM environment
jest.mock('react-force-graph-2d', () => {
  return function MockForceGraph() {
    return <div data-testid="force-graph" />;
  };
});

const mockData = {
  nodes: [
    { id: '1', labels: ['Program'], properties: { name: 'Test Program' } },
    { id: '2', labels: ['Finding'], properties: { vuln_type: 'XSS', severity: 'High' } }
  ],
  links: [
    { source: '1', target: '2', type: 'HAS_FINDING' }
  ]
};

describe('AttackSurfaceGraph', () => {
  it('renders without crashing', () => {
    render(<AttackSurfaceGraph data={mockData} onNodeClick={() => {}} />);
    expect(screen.getByTestId('force-graph')).toBeInTheDocument();
  });
});
