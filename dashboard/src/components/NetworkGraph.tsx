import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { NetworkData, AttackPath } from '../types';

interface Props {
  network: NetworkData;
  activePath?: AttackPath | null;
  verifiedPathIds?: string[];
}

const ROLE_COLORS: Record<string, string> = {
  web:      '#3b82f6',
  app:      '#8b5cf6',
  db:       '#f43f5e',
  database: '#f43f5e',  // alias: facts.json uses "database"; contract uses "db"
  'jump host': '#f59e0b',
};

export default function NetworkGraph({ network, activePath, verifiedPathIds }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const nodes = network.hosts.map(h => ({
      data: {
        id: h.hostname,
        label: h.hostname,
        role: h.role,
        isEntry: h.is_entry_point,
        isCrown: h.is_crown_jewel,
        color: ROLE_COLORS[h.role] ?? '#64748b',
        vectors: h.vectors.length,
      },
    }));

    const edges = network.reachability.map((r, i) => ({
      data: {
        id: `edge-${i}`,
        source: r.from_host,
        target: r.to_host,
        label: `${r.service}:${r.port}`,
      },
    }));

    const cy = cytoscape({
      container: containerRef.current,
      elements: { nodes, edges },
      style: [
        {
          selector: 'node',
          style: {
            'width': 60, 'height': 60,
            'background-color': 'data(color)',
            'background-opacity': 0.2,
            'border-width': 2,
            'border-color': 'data(color)',
            'label': 'data(label)',
            'color': '#f1f5f9',
            'font-size': 10,
            'font-family': 'Inter, sans-serif',
            'font-weight': '600',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-outline-width': 0,
          },
        },
        {
          selector: 'node[?isEntry]',
          style: {
            'border-color': '#00d4ff',
            'background-color': '#00d4ff',
            'background-opacity': 0.18,
            'border-width': 2.5,
            'box-shadow': '0 0 20px rgba(0,212,255,0.6)',
          },
        },
        {
          selector: 'node[?isCrown]',
          style: {
            'border-color': '#f43f5e',
            'background-color': '#f43f5e',
            'background-opacity': 0.18,
            'border-width': 2.5,
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': 'rgba(255,255,255,0.1)',
            'target-arrow-color': 'rgba(255,255,255,0.15)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': 9,
            'color': '#64748b',
            'font-family': 'JetBrains Mono, monospace',
            'text-background-color': '#0a0d14',
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
          },
        },
        {
          selector: '.path-edge',
          style: {
            'line-color': '#00d4ff',
            'target-arrow-color': '#00d4ff',
            'width': 3,
            'line-style': 'solid',
            'opacity': 1,
          },
        },
        {
          selector: '.path-node',
          style: {
            'border-color': '#00d4ff',
            'border-width': 3,
            'background-opacity': 0.35,
          },
        },
        {
          selector: '.verified-edge',
          style: {
            'line-color': '#10b981',
            'target-arrow-color': '#10b981',
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 40,
        spacingFactor: 1.4,
        avoidOverlap: true,
      },
      userZoomingEnabled: true,
      userPanningEnabled: true,
      autoungrabify: false,
    });

    cyRef.current = cy;
    return () => { cy.destroy(); };
  }, [network]);

  // Highlight active attack path
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass('path-edge path-node verified-edge');

    if (!activePath) return;

    const pathNodeIds = new Set<string>();
    activePath.steps.forEach(step => {
      pathNodeIds.add(step.source_host);
      pathNodeIds.add(step.target_host);
    });

    pathNodeIds.forEach(id => cy.$(`#${id}`).addClass('path-node'));

    activePath.steps.forEach((step, i) => {
      if (step.source_host !== step.target_host) {
        const edge = cy.edges().filter(
          e => e.data('source') === step.source_host && e.data('target') === step.target_host
        );
        if (edge.length) {
          edge.addClass('path-edge');
          if (verifiedPathIds?.includes(activePath.path_id)) {
            edge.addClass('verified-edge');
          }
        }
      }
    });
  }, [activePath, verifiedPathIds]);

  return (
    <div style={{ position: 'relative' }}>
      <div ref={containerRef} className="cyto-container" />
      <div className="cyto-legend">
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#00d4ff' }} />
          Entry Point
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#f43f5e' }} />
          Crown Jewel
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#3b82f6' }} />
          Web
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#8b5cf6' }} />
          App
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#00d4ff', opacity: 0.7 }} />
          Attack Path
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#10b981' }} />
          Verified
        </div>
      </div>
    </div>
  );
}
