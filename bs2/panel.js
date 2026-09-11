"use strict";
const el = id => document.getElementById(id);
async function refresh() {
  try {
    const response = await fetch('/api/state', {cache:'no-store'});
    if (!response.ok) throw new Error(`State unavailable (${response.status})`);
    const state = await response.json();
    el('status').textContent = `${state.battle} · ${state.receipt_count} receipts · ${state.unresolved_intents.length} unresolved dispatches · read-only`;
    el('error').textContent = '';
    for (const key of ['known','suspected','already_tried','changed']) {
      el(key).replaceChildren();
      if (!state[key].length) el(key).textContent = 'Nothing recorded yet.';
      for (const item of state[key]) {
        const div = document.createElement('div'); div.className = 'item';
        const p = document.createElement('p'); p.textContent = item.summary || item.content || `${item.reason}: ${(item.changed || []).join(', ')}`; div.append(p);
        const match = (item.source || '').match(/:event:(\d+):/);
        if (match) { const a = document.createElement('a'); a.href = `/api/event/${match[1]}`; a.textContent = `Source receipt ${match[1]} · ${item.status}`; div.append(a); }
        el(key).append(div);
      }
    }
    el('context').textContent = state.context.text;
    el('context-meta').textContent = state.context.context_hash ? `Hash ${state.context.context_hash} · ${state.context.stats.shed_count} items outside slice budget` : 'No manager turn yet';
    el('next').textContent = state.next_check;
    el('tutor').replaceChildren();
    for (const [label, value] of Object.entries(state.tutor)) { const p=document.createElement('p'); const b=document.createElement('strong'); b.textContent=label+': '; p.append(b,document.createTextNode(value)); el('tutor').append(p); }
  } catch (error) { el('error').textContent = error.message + ' — displayed data may be stale.'; }
}
refresh(); setInterval(refresh, 5000);
