// Only presentation intent and the last explicit query response are retained.
// Inventory always arrives as a fresh Rust-rendered authoritative projection.
(() => {
  let saved = null;
  let busy = false;
  let result = null;
  let epoch = 0;
  const inspector = () => document.querySelector('#mdns-inspector');

  function showResult() {
    const output = document.querySelector('#mdns-query-result');
    if (!output || !result) return;
    output.replaceChildren();
    output.dataset.outcome = result.outcome;
    const title = document.createElement('p');
    title.textContent = `${result.request} · ${result.outcome === 'started' ? 'Started' : result.outcome === 'answers' ? 'Answers received' : result.outcome === 'no_answer' ? 'No answer received' : result.outcome === 'pending' ? 'Waiting for query response' : 'Query failed'}: ${result.message}`;
    output.append(title);
    if (result.observed_at) {
      const at = document.createElement('p');
      at.textContent = `Response observed ${result.observed_at}${result.query ? ` · ${result.query}` : ''}`;
      output.append(at);
    }
    if (result.service_types?.length) {
      const types = document.createElement('pre');
      types.textContent = result.service_types.join('\n');
      output.append(types);
    }
    if (result.records?.length) {
      const details = document.createElement('details');
      details.open = true;
      const summary = document.createElement('summary');
      summary.id = 'mdns-query-records-summary';
      summary.dataset.focusKey = 'mdns-query-records-summary';
      summary.textContent = `${result.records.length} returned records · query response`;
      const records = document.createElement('pre');
      records.textContent = JSON.stringify(result.records, null, 2);
      details.append(summary, records);
      output.append(details);
    }
  }

  function beforeRefresh() {
    const root = inspector();
    if (!root) { saved = null; return; }
    saved = {
      query: document.querySelector('.app-shell')?.dataset.uiQuery,
      inputs: [...root.querySelectorAll('input:not([type="hidden"]), select')].map(node => [node.id || node.name, node.value]),
      opened: [...root.querySelectorAll('details[data-mdns-detail][open]')].map(node => node.dataset.mdnsDetail),
    };
  }
  function afterRefresh() {
    const root = inspector();
    if (!root) return;
    if (saved) {
      for (const node of root.querySelectorAll('input:not([type="hidden"]), select')) {
        const entry = saved.inputs.find(([key]) => key === (node.id || node.name));
        // Filters are authoritative URL intent after an explicit Apply. Only query drafts persist.
        if (entry && (node.closest('[data-mdns-kind]') || saved.query === document.querySelector('.app-shell')?.dataset.uiQuery)) node.value = entry[1];
      }
      for (const node of root.querySelectorAll('details[data-mdns-detail]')) node.open = saved.opened.includes(node.dataset.mdnsDetail);
    }
    for (const button of root.querySelectorAll('[data-mdns-kind] button')) button.disabled = busy;
    showResult();
  }

  document.addEventListener('submit', async event => {
    const form = event.target.closest('form[data-mdns-kind]');
    if (!form) return;
    event.preventDefault();
    if (busy) return;
    const kind = form.dataset.mdnsKind;
    const value = form.querySelector('[name="value"]')?.value.trim();
    const request = value ? `${kind === 'browse' ? 'Browse' : 'Resolve'} ${value}` : 'Restart discovery';
    const requestEpoch = epoch;
    busy = true;
    result = {outcome:'pending',request,message:'The network may take a few seconds to respond.'};
    beforeRefresh();
    afterRefresh();
    try {
      if (!window.KoiOperator?.perform) throw new Error('The authenticated query connection is unavailable.');
      const response = await window.KoiOperator.perform('ui_mdns_query', {kind, ...(value ? {value} : {})});
      if (requestEpoch !== epoch) return;
      if (!['answers','no_answer','error','started'].includes(response?.outcome)) throw new Error('The query returned an unrecognized result. Refresh and try again.');
      result = {...response, request};
    } catch (error) {
      if (requestEpoch !== epoch) return;
      result = {outcome:'error',request,message: typeof error === 'string' ? error : error?.message || 'The query failed.'};
    } finally {
      if (requestEpoch !== epoch) return;
      busy = false;
      showResult();
      try { await window.KoiOperator?.refresh?.(); }
      catch { /* Query response remains useful even if the subsequent snapshot read failed. */ }
      afterRefresh();
    }
  });
  function reset() { epoch += 1; saved = null; result = null; busy = false; document.querySelector('#mdns-query-result')?.replaceChildren(); }
  window.KoiMdns = {beforeRefresh, afterRefresh, isBusy: () => busy, reset};
})();
