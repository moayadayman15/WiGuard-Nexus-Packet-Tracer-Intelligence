(function(){
  const input = document.getElementById('file-input');
  const label = document.getElementById('file-name');
  const drop = document.getElementById('dropzone');
  const uploadStatus = document.getElementById('upload-status');
  const companionInput = document.getElementById('companion-input');
  const companionLabel = document.getElementById('companion-name');
  const uploadForm = document.querySelector('form.upload-box');

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

  const describePrimaryFile = () => {
    const file = input?.files?.[0];
    if (!file) {
      if (label) label.textContent = 'No file selected';
      setUploadStatus('Waiting for file. Conversion runs automatically in the background after upload.');
      return;
    }
    if (label) label.textContent = `${file.name} • ${formatBytes(file.size)}`;
    const ext = (file.name.split('.').pop() || '').toLowerCase();
    const native = ['pkt', 'pka'].includes(ext);
    const structured = ['xml', 'json', 'txt', 'cfg', 'conf', 'zip'].includes(ext);
    if (native) {
      setUploadStatus(`Native Packet Tracer selected (${formatBytes(file.size)}). WiGuard will run converter probe, printable recovery, XML bridge, JSON normalization, object extraction, and evidence grading.`, true);
    } else if (structured) {
      setUploadStatus(`Structured evidence selected (${formatBytes(file.size)}). WiGuard will parse directly, validate traceability, and generate reviewer-ready extraction artifacts.`, true);
    } else {
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
  if (uploadForm) {
    uploadForm.addEventListener('submit', () => {
      const primary = input?.files?.[0];
      const companion = companionInput?.files?.[0];
      const source = primary ? primary.name : 'selected evidence';
      const companionNote = companion ? ` Companion export ${companion.name} is included for stronger verification.` : '';
      setUploadStatus(`Processing ${source} now. Conversion, extraction, validation, and artifact generation are running in the backend.${companionNote}`, true);
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
