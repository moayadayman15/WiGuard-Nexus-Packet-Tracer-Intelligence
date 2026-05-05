(function(){
  const input = document.getElementById('file-input');
  const label = document.getElementById('file-name');
  const drop = document.getElementById('dropzone');
  const uploadStatus = document.getElementById('upload-status');
  const companionInput = document.getElementById('companion-input');
  const companionLabel = document.getElementById('companion-name');
  const uploadForm = document.querySelector('form.upload-box');

  const escapeHtml = (value) => String(value ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));

  const formatBytes = (bytes) => {
    const size = Number(bytes || 0);
    if (!size) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = size;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
  };

  const setUploadStatus = (message, running = false) => {
    if (!uploadStatus) return;
    uploadStatus.textContent = message;
    uploadStatus.classList.toggle('running', !!running);
  };

  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };

  const setDropMode = (mode) => {
    if (!drop) return;
    drop.classList.remove('mode-native', 'mode-structured', 'mode-unknown');
    if (mode) drop.classList.add(`mode-${mode}`);
  };

  const describePrimaryFile = () => {
    const file = input?.files?.[0];
    if (!file) {
      if (label) label.textContent = 'No file selected';
      setText('selected-file-kind', 'Waiting');
      setText('selected-file-size', '—');
      setText('selected-file-mode', 'Auto');
      setText('selected-file-extension', 'Choose a file to classify the import path.');
      setText('selected-file-pipeline', 'Intake → decode → normalize → validate.');
      setDropMode('unknown');
      setUploadStatus('Waiting for file. Conversion runs automatically in the background after upload.');
      return;
    }
    if (label) label.textContent = `${file.name} • ${formatBytes(file.size)}`;
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const native = ['pkt', 'pka'].includes(ext);
    const structured = ['xml', 'json', 'txt', 'cfg', 'conf', 'log', 'zip'].includes(ext);
    setText('selected-file-size', formatBytes(file.size));
    setText('selected-file-extension', ext ? `.${ext} evidence selected` : 'Unknown extension');
    if (native) {
      setDropMode('native');
      setText('selected-file-kind', 'Native Packet Tracer');
      setText('selected-file-mode', 'Native recovery lane');
      setText('selected-file-pipeline', 'Intake → converter probe → binary hints → XML bridge → JSON → truth contract.');
      setUploadStatus(`Native Packet Tracer selected (${formatBytes(file.size)}). WiGuard will run converter probe, printable recovery, XML bridge, JSON normalization, object extraction, and evidence grading.`, true);
    } else if (structured) {
      setDropMode('structured');
      setText('selected-file-kind', ext === 'zip' ? 'Evidence bundle' : 'Structured evidence');
      setText('selected-file-mode', 'Verified parse lane');
      setText('selected-file-pipeline', 'Intake → direct parser → object extraction → line mapping → artifacts.');
      setUploadStatus(`Structured evidence selected (${formatBytes(file.size)}). WiGuard will parse directly, validate traceability, and generate reviewer-ready extraction artifacts.`, true);
    } else {
      setDropMode('unknown');
      setText('selected-file-kind', 'Unknown evidence');
      setText('selected-file-mode', 'Safe review lane');
      setText('selected-file-pipeline', 'Intake → safe classification → warnings → analyst next step.');
      setUploadStatus(`File selected: ${file.name}. WiGuard will attempt import and classify the real conversion path after upload.`, true);
    }
  };

  const describeCompanionFile = () => {
    const file = companionInput?.files?.[0];
    if (!companionLabel) return;
    companionLabel.textContent = file ? `${file.name} • ${formatBytes(file.size)}` : 'No companion export selected';
    if (file) {
      setUploadStatus(`Companion export attached (${formatBytes(file.size)}). Native PKT recovery will be cross-checked against exported evidence wherever possible.`, true);
    } else {
      describePrimaryFile();
    }
  };

  if (input) input.addEventListener('change', describePrimaryFile);
  if (companionInput) companionInput.addEventListener('change', describeCompanionFile);
  const ensureLivePanel = () => {
    let panel = document.getElementById('upload-live-result');
    if (!panel && uploadStatus) {
      panel = document.createElement('div');
      panel.id = 'upload-live-result';
      panel.className = 'upload-live-result';
      uploadStatus.insertAdjacentElement('afterend', panel);
    }
    return panel;
  };

  const stageClass = (status) => {
    const value = String(status || '').toLowerCase();
    if (['success', 'understood', 'excellent', 'good', 'pass', 'completed'].includes(value)) return 'success';
    if (['failed', 'fail', 'error', 'blocked'].includes(value)) return 'error';
    if (['review', 'partial', 'limited', 'needs_more_evidence', 'skipped'].includes(value)) return 'review';
    return 'info';
  };


  const scorePercent = (value) => {
    const n = Number(value || 0);
    if (!Number.isFinite(n)) return 0;
    return Math.max(0, Math.min(100, Math.round(n <= 1 ? n * 100 : n)));
  };

  const setTrustItem = (id, textId, statusClass, text) => {
    const item = document.getElementById(id);
    const label = document.getElementById(textId);
    if (item) {
      item.classList.remove('idle', 'pass', 'review', 'error');
      item.classList.add(statusClass);
    }
    if (label) label.textContent = text;
  };

  const updateReadinessPanel = (data) => {
    if (!data) return;
    const profile = data.profile || {};
    const contract = data.contract || {};
    const counts = data.counts || {};
    const breakdown = data.count_breakdown || {};
    const objectsTotal = Number(breakdown.real_object_count || data.object_count || 0);
    const evidenceTotal = Number(breakdown.evidence_entry_count || data.evidence_entry_count || 0);
    const score = scorePercent(profile.readiness_score || data.readiness_score || 0);
    const sourceMode = data.source_mode || profile.source_mode || 'classified';
    const readinessRaw = String(profile.readiness || (score >= 70 ? 'good' : score > 0 ? 'needs_more_evidence' : 'review'));
    const ring = document.getElementById('readiness-ring');
    const percent = document.getElementById('readiness-percent');
    const badge = document.getElementById('readiness-badge');
    if (ring) ring.style.setProperty('--score', score);
    if (percent) percent.textContent = `${score}%`;
    if (badge) {
      badge.className = `badge ${readinessRaw.replaceAll('_','-')}`;
      badge.textContent = readinessRaw.replaceAll('_', ' ');
    }
    setTrustItem('trust-file', 'trust-file-text', data.filename ? 'pass' : 'idle', data.filename || 'Not uploaded yet');
    setTrustItem('trust-parser', 'trust-parser-text', sourceMode ? 'pass' : 'idle', sourceMode || 'Waiting for classification');
    setTrustItem('trust-objects', 'trust-objects-text', (objectsTotal + evidenceTotal) > 0 ? 'pass' : 'review', `${objectsTotal} real objects · ${evidenceTotal} evidence rows`);
    const reportSafe = !!(contract.can_publish_technical || contract.can_claim_full_fidelity || objectsTotal > 0);
    setTrustItem('trust-report', 'trust-report-text', reportSafe ? 'pass' : 'review', String(contract.tier || (reportSafe ? 'technical report with limitations' : 'waiting for import')).replaceAll('_',' '));
    setText('readiness-mode', sourceMode || 'N/A');
    setText('readiness-size', profile.bytes ? `${Number(profile.bytes).toLocaleString()} bytes` : (data.file_size ? `${Number(data.file_size).toLocaleString()} bytes` : 'stored'));
    setText('readiness-objects', String(objectsTotal));
    setText('readiness-evidence', String(evidenceTotal));
    setText('readiness-lines', String(profile.printable_lines || 0));
    setText('readiness-next-step', profile.analyst_next_step || data.message || 'Import completed. Review extracted evidence and open the workspace.');
    const rail = document.getElementById('conversion-pipeline-rail');
    if (rail && Array.isArray(data.pipeline) && data.pipeline.length) {
      rail.classList.add('pipeline-rail');
      rail.classList.remove('empty-inline-note');
      rail.innerHTML = data.pipeline.slice(0, 6).map((step, idx) => `
        <article class="${stageClass(step.status).replaceAll('_','-')}">
          <span class="step-index">${idx + 1}</span>
          <div><b>${escapeHtml(step.stage || 'Pipeline stage')}</b><small>${Math.round(Number(step.confidence || 0) * 100)}% confidence · ${Number(step.items || 0)} items</small></div>
        </article>`).join('');
    }
  };

  const renderUploadLiveResult = (data) => {
    const panel = ensureLivePanel();
    if (!panel) return;
    const counts = data.counts || {};
    const breakdown = data.count_breakdown || {};
    const topCounts = ['devices','interfaces','vlans','acl_rules','source_key_value_index','universal_network_facts','payload_tables','native_source_manifest','internal_xml_bridge','decoded_payloads','raw_evidence']
      .map((key) => `<article><span>${escapeHtml(key.replaceAll('_',' '))}</span><b>${Number(counts[key] || 0)}</b></article>`)
      .join('');
    const pipeline = (data.pipeline || []).slice(0, 6)
      .map((step, idx) => `<article class="${stageClass(step.status)}"><b>${idx + 1}. ${escapeHtml(step.stage || 'Stage')}</b><small>${escapeHtml(step.status || 'status')} · ${Math.round(Number(step.confidence || 0) * 100)}% · ${Number(step.items || 0)} item(s)</small><p>${escapeHtml(step.detail || '')}</p></article>`)
      .join('');
    const profile = data.profile || {};
    const bridge = data.bridge || {};
    const contract = data.contract || {};
    const converter = data.external_converter || {};
    panel.innerHTML = `
      <div class="live-result-head">
        <div><span>Live import result</span><b>${escapeHtml(data.filename || 'Uploaded evidence')}</b><small>${escapeHtml(data.message || '')}</small></div>
        <a class="ghost-btn" href="${escapeHtml(data.redirect || window.location.href)}">Open full refreshed workspace</a>
      </div>
      <div class="live-summary-grid">
        <article><span>Source mode</span><b>${escapeHtml(data.source_mode || profile.source_mode || 'unknown')}</b><small>${escapeHtml((data.source_hash || '').slice(0, 16) || 'hash pending')}</small></article>
        <article><span>Readiness</span><b>${Math.round(Number(profile.readiness_score || 0) * 100)}%</b><small>${escapeHtml(profile.readiness || 'review')}</small></article>
        <article><span>XML bridge</span><b>${profile.internal_xml_bridge_used ? 'Used' : 'Direct'}</b><small>${Number(bridge.xml_bytes || 0)} XML bytes → ${Number(bridge.normalized_json_bytes || 0)} JSON bytes</small></article>
        <article><span>External converter</span><b>${Number(converter.outputs || bridge.external_converter_outputs || 0) ? 'Merged' : 'Not used'}</b><small>${Number(converter.outputs || bridge.external_converter_outputs || 0)} XML/JSON output(s)</small></article>
        <article><span>Evidence tier</span><b>${escapeHtml(String(contract.tier || 'review').replaceAll('_',' '))}</b><small>${escapeHtml(contract.can_claim_full_fidelity ? 'full fidelity allowed' : 'truth contract blocks fake 100%')}</small></article>
        <article><span>Real objects</span><b>${Number(breakdown.real_object_count || data.object_count || 0)}</b><small>topology/policy only</small></article>
        <article><span>Evidence rows</span><b>${Number(breakdown.evidence_entry_count || data.evidence_entry_count || 0)}</b><small>payload/native/support entries</small></article>
      </div>
      <div class="live-count-grid">${topCounts}</div>
      <div class="live-pipeline">${pipeline}</div>
      ${profile.analyst_next_step ? `<p class="live-next-step">${escapeHtml(profile.analyst_next_step)}</p>` : ''}
    `;
    panel.classList.toggle('error', !data.ok);
    updateReadinessPanel(data);
  };

  if (uploadForm) {
    uploadForm.addEventListener('submit', async (e) => {
      const primary = input?.files?.[0];
      const companion = companionInput?.files?.[0];
      const source = primary ? primary.name : 'selected evidence';
      const companionNote = companion ? ` Companion export ${companion.name} is included for stronger verification.` : '';
      setUploadStatus(`Processing ${source} now. Conversion, extraction, validation, and artifact generation are running in the backend.${companionNote}`, true);

      if (!window.fetch || !window.FormData) return;
      e.preventDefault();
      const btn = uploadForm.querySelector('button[type="submit"]');
      if (btn) { btn.disabled = true; btn.dataset.originalText = btn.textContent; btn.textContent = 'Processing evidence…'; }
      const panel = ensureLivePanel();
      if (panel) {
        panel.classList.remove('error');
        panel.innerHTML = '<div class="live-processing premium-live-processing"><b>Backend pipeline is running…</b><small>intake → converter probe → XML bridge → normalized JSON → extraction → artifact generation. The result card will show counts even for weak PKT recovery.</small></div>';
      }
      try {
        const formData = new FormData(uploadForm);
        formData.set('response_mode', 'json');
        const res = await fetch(uploadForm.action, {
          method: 'POST',
          body: formData,
          headers: {'Accept': 'application/json', 'X-Requested-With': 'fetch'},
          credentials: 'same-origin',
          redirect: 'follow'
        });
        const contentType = (res.headers.get('content-type') || '').toLowerCase();
        let data;
        if (contentType.includes('application/json')) {
          data = await res.json();
        } else {
          const text = await res.text();
          const looksLikeLogin = /<form[^>]+login|Sign in|Login \| WiGuard/i.test(text) || res.redirected;
          data = {
            ok: false,
            error: looksLikeLogin ? 'authentication_required_or_expired_session' : 'non_json_backend_response',
            message: looksLikeLogin
              ? 'Backend redirected to login/session page. Sign in again, refresh Import Center, then upload.'
              : `Backend returned ${res.status} ${res.statusText || ''} but not JSON. Check the terminal traceback/logs.`,
            redirect: res.url || window.location.href
          };
        }
        renderUploadLiveResult(data);
        if (!res.ok || !data.ok) {
          setUploadStatus(data.message || data.error || 'Import failed. Check backend logs.', false);
        } else {
          setUploadStatus(`${data.message || 'Import completed.'} UI updated live; open the full workspace to refresh every section.`, false);
        }
      } catch (err) {
        setUploadStatus(`Live upload failed: ${err.message}. Browser will fall back if you submit again.`, false);
        const panel = ensureLivePanel();
        if (panel) { panel.classList.add('error'); panel.innerHTML = `<div class="live-processing"><b>Upload failed</b><small>${escapeHtml(err.message || String(err))}</small></div>`; }
      } finally {
        if (btn) { btn.disabled = false; btn.textContent = btn.dataset.originalText || 'Import → Convert → Validate → Generate Artifacts'; }
      }
    });
  }

  if (drop && input) {
    ['dragenter', 'dragover'].forEach((eventName) => {
      drop.addEventListener(eventName, (e) => {
        e.preventDefault();
        drop.classList.add('drag');
      });
    });
    ['dragleave', 'drop'].forEach((eventName) => {
      drop.addEventListener(eventName, (e) => {
        e.preventDefault();
        if (eventName !== 'drop') drop.classList.remove('drag');
      });
    });
    drop.addEventListener('drop', (e) => {
      const files = e.dataTransfer?.files;
      drop.classList.remove('drag');
      if (files?.length) {
        input.files = files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
        describePrimaryFile();
      }
    });
  }
})();


(function(){
  const graph = document.getElementById('topology-graph');
  const topo = window.WIGUARD_TOPOLOGY || {nodes: [], edges: []};
  if(!graph || !topo.nodes || !topo.nodes.length){
    if(graph && !topo.nodes?.length){ graph.innerHTML = '<p class="muted" style="padding:18px">Import evidence first to generate topology.</p>'; }
    return;
  }
  const typeColumn = {
    ssid: 8, vlan: 25, dhcp: 25, interface: 48, switch: 70, router: 70,
    neighbor: 82, acl: 63, control: 82, network: 60, policy: 8, device: 70
  };
  const buckets = {};
  topo.nodes.forEach(n => {
    const type = (n.type || 'device').toLowerCase();
    const col = typeColumn[type] || 60;
    buckets[col] = buckets[col] || [];
    buckets[col].push(n);
  });
  const positions = {};
  Object.keys(buckets).forEach(col => {
    const list = buckets[col];
    list.forEach((n, idx) => {
      const y = 10 + ((idx + 1) * (80 / (list.length + 1)));
      positions[n.id] = {x: Number(col), y};
    });
  });
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('class', 'topology-svg');
  svg.setAttribute('viewBox', '0 0 100 100');
  svg.setAttribute('preserveAspectRatio', 'none');
  const defs = document.createElementNS(svgNS, 'defs');
  const marker = document.createElementNS(svgNS, 'marker');
  marker.setAttribute('id','arrow'); marker.setAttribute('viewBox','0 0 10 10'); marker.setAttribute('refX','9'); marker.setAttribute('refY','5'); marker.setAttribute('markerWidth','4'); marker.setAttribute('markerHeight','4'); marker.setAttribute('orient','auto-start-reverse');
  const path = document.createElementNS(svgNS, 'path');
  path.setAttribute('d','M 0 0 L 10 5 L 0 10 z'); path.setAttribute('fill','rgba(125,211,252,.58)');
  marker.appendChild(path); defs.appendChild(marker); svg.appendChild(defs);
  topo.edges.forEach((e, idx) => {
    const a = positions[e.from], b = positions[e.to];
    if(!a || !b) return;
    const line = document.createElementNS(svgNS, 'path');
    const mid = (a.x + b.x) / 2;
    const bend = idx % 2 ? -5 : 5;
    line.setAttribute('d', `M ${a.x} ${a.y} C ${mid} ${a.y + bend}, ${mid} ${b.y - bend}, ${b.x} ${b.y}`);
    const strong = ['confirmed','enforced','expected','pass'].includes(String(e.status || '').toLowerCase());
    line.setAttribute('fill', 'none');
    line.setAttribute('stroke', strong ? 'rgba(34,211,238,.62)' : 'rgba(148,163,184,.34)');
    line.setAttribute('stroke-width', strong ? '0.38' : '0.24');
    line.setAttribute('stroke-dasharray', strong ? '0' : '1.2 1.2');
    line.setAttribute('marker-end', 'url(#arrow)');
    svg.appendChild(line);
    if(e.type){
      const label = document.createElement('span');
      label.className = 'topo-edge-label';
      label.style.left = `${mid}%`;
      label.style.top = `${(a.y + b.y) / 2}%`;
      label.textContent = e.type;
      graph.appendChild(label);
    }
  });
  graph.prepend(svg);
  topo.nodes.forEach(n => {
    const pos = positions[n.id]; if(!pos) return;
    const node = document.createElement('div');
    const type = (n.type || 'device').toLowerCase().replace(/[^a-z0-9_-]/g,'_');
    node.className = `topo-node dynamic type-${type}`;
    node.style.left = `calc(${pos.x}% - 78px)`;
    node.style.top = `calc(${pos.y}% - 38px)`;
    const conf = Math.round((Number(n.confidence || 0)) * 100);
    const meta = n.meta || {};
    node.innerHTML = `<b>${escapeHtml(n.label || n.id)}</b><small>${escapeHtml(n.type || 'node')} · ${conf}%${meta.status ? ' · '+escapeHtml(meta.status) : ''}</small>`;
    node.title = JSON.stringify(n.meta || {}, null, 2);
    node.addEventListener('click', () => {
      graph.querySelectorAll('.topo-node.selected').forEach(x => x.classList.remove('selected'));
      node.classList.add('selected');
    });
    graph.appendChild(node);
  });
  function escapeHtml(value){
    return String(value ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));
  }
})();


(function(){
  // v5.8 UX: safe destructive actions, client-side table search, and smoother preview panels.
  document.querySelectorAll('form button.danger, form[data-confirm]').forEach(btn => {
    const form = btn.closest('form');
    if(!form || form.dataset.confirmBound) return;
    form.dataset.confirmBound = '1';
    form.addEventListener('submit', (e) => {
      const msg = form.getAttribute('data-confirm') || 'Confirm this action?';
      if(!window.confirm(msg)){ e.preventDefault(); }
    });
  });

  document.querySelectorAll('.table-wrap').forEach((wrap, idx) => {
    const table = wrap.querySelector('table');
    if(!table || wrap.dataset.searchReady) return;
    wrap.dataset.searchReady = '1';
    const rows = Array.from(table.querySelectorAll('tbody tr'));
    if(rows.length < 6) return;
    const input = document.createElement('input');
    input.className = 'table-search';
    input.placeholder = 'Search this table...';
    input.setAttribute('aria-label', 'Search table');
    wrap.insertBefore(input, table);
    input.addEventListener('input', () => {
      const q = input.value.trim().toLowerCase();
      rows.forEach(row => {
        row.style.display = !q || row.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    });
  });

  document.querySelectorAll('[data-copy]').forEach(el => {
    el.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(el.getAttribute('data-copy'));
        el.classList.add('copied');
        setTimeout(()=>el.classList.remove('copied'), 900);
      } catch(err) {}
    });
  });
})();

// v5.11 workspace interactions
(function(){
  const search = document.getElementById('workspace-object-search');
  const rows = Array.from(document.querySelectorAll('#workspace-object-tree .object-row'));
  if(search){
    search.addEventListener('input', function(){
      const q = this.value.trim().toLowerCase();
      rows.forEach(row => { row.style.display = !q || (row.dataset.search||row.textContent||'').toLowerCase().includes(q) ? '' : 'none'; });
    });
  }
  const detail = document.getElementById('node-detail-panel');
  document.querySelectorAll('.workspace-node').forEach(btn => {
    btn.addEventListener('click', () => {
      if(!detail) return;
      let data = {};
      try { data = JSON.parse(btn.dataset.node || '{}'); } catch(e) {}
      const label = data.label || btn.innerText || 'Node';
      const type = data.type || 'network-node';
      const confidence = Math.round(((data.confidence || 0.5) * 100));
      detail.innerHTML = `<b>${label}</b><span>Type: ${type} · Confidence: ${confidence}%</span><pre>${escapeHtml(JSON.stringify(data, null, 2)).slice(0, 1200)}</pre>`;
    });
  });
  function escapeHtml(str){ return String(str).replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#039;','"':'&quot;'}[c])); }
})();

// v5.12.5 Import Center density controller and safer drag/drop file assignment.
(function(){
  const toolbar = document.querySelector('[data-import-view-toolbar]');
  if(!toolbar) return;
  const body = document.body;
  const buttons = Array.from(toolbar.querySelectorAll('[data-import-view]'));
  const allowed = new Set(['executive','analyst','deep']);
  const preferred = localStorage.getItem('wiguard.import.view') || 'executive';
  function apply(mode){
    const selected = allowed.has(mode) ? mode : 'executive';
    body.classList.remove('import-view-executive','import-view-analyst','import-view-deep');
    body.classList.add(`import-view-${selected}`);
    buttons.forEach(btn => btn.classList.toggle('active', btn.dataset.importView === selected));
    localStorage.setItem('wiguard.import.view', selected);
    const vault = document.querySelector('.advanced-evidence-vault');
    if(vault && selected === 'deep') vault.open = true;
    if(vault && selected === 'executive') vault.open = false;
  }
  buttons.forEach(btn => btn.addEventListener('click', () => apply(btn.dataset.importView)));
  apply(preferred);
})();

(function(){
  const input = document.getElementById('file-input');
  const drop = document.getElementById('dropzone');
  if(!input || !drop || drop.dataset.safeDropBound) return;
  drop.dataset.safeDropBound = '1';
  function assignFiles(files){
    if(!files || !files.length) return false;
    try {
      const dt = new DataTransfer();
      Array.from(files).forEach(file => dt.items.add(file));
      input.files = dt.files;
    } catch(err) {
      try { input.files = files; } catch(_) { return false; }
    }
    input.dispatchEvent(new Event('change', {bubbles:true}));
    return true;
  }
  drop.addEventListener('drop', (event) => {
    const files = event.dataTransfer && event.dataTransfer.files;
    if(files && files.length) assignFiles(files);
  }, true);
})();

// v5.15.0 global command palette and cleaner product navigation
(function(){
  const palette = document.getElementById('command-palette');
  const input = document.getElementById('command-palette-search');
  const results = document.getElementById('command-palette-results');
  if(!palette || !input || !results) return;
  const links = Array.from(document.querySelectorAll('.sidebar .nav a'))
    .filter(a => a.href && a.textContent.trim())
    .map((a, idx) => ({title: a.textContent.trim().replace(/\s+/g,' '), href: a.href, group: a.closest('details') ? 'Advanced' : 'Workflow', idx}));
  let activeIndex = 0;
  function escapeHtml(value){ return String(value ?? '').replace(/[&<>'"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch])); }
  function filtered(){
    const q = input.value.trim().toLowerCase();
    return links.filter(item => !q || item.title.toLowerCase().includes(q) || item.group.toLowerCase().includes(q)).slice(0, 12);
  }
  function render(){
    const list = filtered();
    activeIndex = Math.min(activeIndex, Math.max(0, list.length - 1));
    results.innerHTML = list.map((item, idx) => `<a class="${idx === activeIndex ? 'active' : ''}" href="${escapeHtml(item.href)}"><b>${escapeHtml(item.title)}</b><span>${escapeHtml(item.group)}</span></a>`).join('') || '<p class="muted" style="padding:12px">No matching page.</p>';
  }
  function open(){
    palette.classList.add('open');
    palette.setAttribute('aria-hidden','false');
    input.value = '';
    activeIndex = 0;
    render();
    setTimeout(() => input.focus(), 20);
  }
  function close(){
    palette.classList.remove('open');
    palette.setAttribute('aria-hidden','true');
  }
  document.querySelectorAll('[data-command-palette-open]').forEach(btn => btn.addEventListener('click', open));
  document.querySelectorAll('[data-command-palette-close]').forEach(btn => btn.addEventListener('click', close));
  input.addEventListener('input', () => { activeIndex = 0; render(); });
  input.addEventListener('keydown', (e) => {
    const list = filtered();
    if(e.key === 'ArrowDown'){ e.preventDefault(); activeIndex = Math.min(list.length - 1, activeIndex + 1); render(); }
    if(e.key === 'ArrowUp'){ e.preventDefault(); activeIndex = Math.max(0, activeIndex - 1); render(); }
    if(e.key === 'Enter' && list[activeIndex]){ window.location.href = list[activeIndex].href; }
  });
  document.addEventListener('keydown', (e) => {
    const key = String(e.key || '').toLowerCase();
    if((e.ctrlKey || e.metaKey) && key === 'k'){ e.preventDefault(); open(); }
    if(e.key === 'Escape' && palette.classList.contains('open')) close();
  });
})();
