import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { NetworkData, AttackPath } from '../types';

interface Props {
  network: NetworkData;
  activePath?: AttackPath | null;
  verifiedPathIds?: string[];
  partialPathIds?: string[];
}

/**
 * Fixed left-to-right positions along the attack direction.
 * web01 → app01 → db01: entry → pivot → crown jewel.
 * The physical story should be immediately legible without reading labels.
 */
const HOST_ORDER: Record<string, number> = {
  web01: 0,
  app01: 1,
  db01:  2,
};

const ROLE_LABELS: Record<string, string> = {
  web:      'Web Server',
  app:      'App Server',
  db:       'Database',
  database: 'Database',
  'jump host': 'Jump Host',
};

export default function NetworkGraph({ network, activePath, verifiedPathIds, partialPathIds }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const nodes = network.hosts.map(h => ({
      data: {
        id: h.hostname,
        label: h.hostname,
        role: h.role,
        roleLabel: ROLE_LABELS[h.role] ?? h.role,
        isEntry: h.is_entry_point,
        isCrown: h.is_crown_jewel,
        vectors: h.vectors.length,
        nodeLabel: `${h.hostname}\n${ROLE_LABELS[h.role] ?? h.role}\n${h.vectors.length} vector${h.vectors.length !== 1 ? 's' : ''}`,
      },
    }));

    const edges = network.reachability.map((r, i) => ({
      data: {
        id: `edge-${i}`,
        source: r.from_host,
        target: r.to_host,
        service: `${r.service}:${r.port}`,
        defaultLabel: `${r.service}:${r.port}`,
        label: `${r.service}:${r.port}`,
      },
    }));

    const cy = cytoscape({
      container: containerRef.current,
      elements: { nodes, edges },
      style: [
        // ── Default node: flat card-like appearance ──
        {
          selector: 'node',
          style: {
            'shape': 'round-rectangle',
            'width': 120, 'height': 70,
            'background-color': '#1A1C23',
            'background-opacity': 1,
            'border-width': 1.5,
            'border-color': '#2A2D36',
            'label': 'data(nodeLabel)',
            'color': '#E7E8EC',
            'font-size': 10,
            'font-family': 'IBM Plex Sans, sans-serif',
            'font-weight': 500,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '110px',
            'text-outline-width': 0,
          },
        },
        // ── Entry point ──
        {
          selector: 'node[?isEntry]',
          style: {
            'border-color': '#C9A34E',
            'border-width': 2,
          },
        },
        // ── Crown jewel ──
        {
          selector: 'node[?isCrown]',
          style: {
            'border-color': '#B5584B',
            'border-width': 2,
          },
        },
        // ── Default edge: muted, dashed (unverified) ──
        {
          selector: 'edge',
          style: {
            'width': 1.5,
            'line-color': '#3A3D48',
            'target-arrow-color': '#3A3D48',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.8,
            'curve-style': 'bezier',
            'line-style': 'dashed',
            'line-dash-pattern': [6, 4],
            'label': 'data(label)',
            'font-size': 9,
            'color': '#5F6270',
            'font-family': 'IBM Plex Mono, monospace',
            'text-background-color': '#13151A',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
          },
        },
        // ── Active path edge highlight ──
        {
          selector: '.path-edge',
          style: {
            'line-color': '#C9A34E',
            'target-arrow-color': '#C9A34E',
            'width': 2.5,
            'line-style': 'dashed',
            'line-dash-pattern': [6, 4],
            'opacity': 1,
          },
        },
        // ── Active path node highlight ──
        {
          selector: '.path-node',
          style: {
            'border-color': '#C9A34E',
            'border-width': 2.5,
          },
        },
        // ── Verified edge: solid, green ──
        {
          selector: '.verified-edge',
          style: {
            'line-color': '#4F9E7C',
            'target-arrow-color': '#4F9E7C',
            'line-style': 'solid',
            'width': 2.5,
          },
        },
        // ── Partial edge: dotted, amber ──
        {
          selector: '.partial-edge',
          style: {
            'line-color': '#C9A34E',
            'target-arrow-color': '#C9A34E',
            'line-style': 'dotted',
            'line-dash-pattern': [2, 4],
            'width': 2,
          },
        },
      ],
      // ── Preset layout: fixed left-to-right positions ──
      layout: {
        name: 'preset',
        positions: (node: any) => {
          const hostname = node.data('id');
          const order = HOST_ORDER[hostname] ?? 0;
          const containerW = containerRef.current?.clientWidth ?? 600;
          const containerH = containerRef.current?.clientHeight ?? 400;
          const usableW = containerW - 200;
          const x = 100 + order * (usableW / 2);
          const y = containerH / 2 - 20; // leave room for legend at bottom
          return { x, y };
        },
        padding: 40,
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

    cy.elements().removeClass('path-edge path-node verified-edge partial-edge');
    cy.edges().forEach(e => {
      e.data('label', e.data('defaultLabel'));
    });

    if (!activePath) return;

    const pathNodeIds = new Set<string>();
    activePath.steps.forEach(step => {
      pathNodeIds.add(step.source_host);
      pathNodeIds.add(step.target_host);
    });

    pathNodeIds.forEach(id => cy.$(`#${id}`).addClass('path-node'));

    const isVerified = verifiedPathIds?.includes(activePath.path_id);
    const isPartial = partialPathIds?.includes(activePath.path_id);

    activePath.steps.forEach(step => {
      if (step.source_host !== step.target_host) {
        const edge = cy.edges().filter(
          e => e.data('source') === step.source_host && e.data('target') === step.target_host
        );
        if (edge.length) {
          edge.addClass('path-edge');
          const tech = step.vector.technique;
          const svc = edge.data('service');
          edge.data('label', tech ? `${tech} (${svc})` : svc);
          if (isVerified) {
            edge.addClass('verified-edge');
          } else if (isPartial) {
            edge.addClass('partial-edge');
          }
        }
      }
    });
  }, [activePath, verifiedPathIds, partialPathIds]);

  return (
    <div style={{ position: 'relative' }}>
      <div ref={containerRef} className="cyto-container" />
      <div className="cyto-legend">
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#C9A34E', borderRadius: 2 }} />
          Entry Point
        </div>
        <div className="legend-item">
          <div className="legend-dot" style={{ background: '#B5584B', borderRadius: 2 }} />
          Crown Jewel
        </div>
        <div className="legend-item" style={{ gap: 6 }}>
          <div className="legend-line" style={{ color: '#4F9E7C' }} />
          Verified (solid)
        </div>
        <div className="legend-item" style={{ gap: 6 }}>
          <div className="legend-line dotted" style={{ color: '#C9A34E' }} />
          Partial (dotted)
        </div>
        <div className="legend-item" style={{ gap: 6 }}>
          <div className="legend-line dashed" style={{ color: '#3A3D48' }} />
          Unverified (dashed)
        </div>
      </div>
    </div>
  );
}
