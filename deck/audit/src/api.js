import React from 'react';

export const NODES = [
  { id: 'NODE_01', url: 'http://127.0.0.1:8001' },
  { id: 'NODE_02', url: 'http://127.0.0.1:8002' },
  { id: 'NODE_03', url: 'http://127.0.0.1:8003' },
  { id: 'NODE_04', url: 'http://127.0.0.1:8004' },
];

export function shortHash(value) {
  if (!value || typeof value !== 'string') return '—';
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}
