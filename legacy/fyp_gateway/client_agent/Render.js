// =====================================================================
// PQ Tunneling — renderer process script
// =====================================================================

// ---- Optional Electron window controls (safe no-op outside Electron) ----
let ipcRenderer = null;
try { ipcRenderer = require('electron').ipcRenderer; } catch (e) { /* running in plain browser preview */ }

// Titlebar Window Controls
document.getElementById('wcMin')?.addEventListener('click', () => {
  window.electronAPI?.sendMinimize();
});

document.getElementById('wcMax')?.addEventListener('click', () => {
  window.electronAPI?.sendMaximize();
});

document.getElementById('wcClose')?.addEventListener('click', () => {
  window.electronAPI?.sendClose();
});

//document.getElementById('wcMin').addEventListener('click', () => ipcRenderer && ipcRenderer.send('window-minimize'));
//document.getElementById('wcMax').addEventListener('click', () => ipcRenderer && ipcRenderer.send('window-maximize'));
//document.getElementById('wcClose').addEventListener('click', () => ipcRenderer && ipcRenderer.send('window-close'));

// =====================================================================
// DATA
// =====================================================================
const COUNTRIES = [
  { id: 'fastest', name: 'Fastest Node', flag: '⚡', servers: 'Auto-selected', tier: 'high', fastest: true, x: 505, y: 165 },
  { id: 'af', name: 'Afghanistan', flag: '🇦🇫', servers: '4 servers', tier: 'med', x: 640, y: 195 },
  { id: 'al', name: 'Albania', flag: '🇦🇱', servers: '6 servers', tier: 'high', x: 545, y: 155 },
  { id: 'dz', name: 'Algeria', flag: '🇩🇿', servers: '8 servers', tier: 'high', x: 500, y: 195 },
  { id: 'us', name: 'United States', flag: '🇺🇸', servers: '312 servers', tier: 'high', x: 210, y: 165 },
  { id: 'de', name: 'Germany', flag: '🇩🇪', servers: '184 servers', tier: 'high', x: 505, y: 130 },
  { id: 'jp', name: 'Japan', flag: '🇯🇵', servers: '96 servers', tier: 'high', x: 855, y: 175 },
  { id: 'br', name: 'Brazil', flag: '🇧🇷', servers: '52 servers', tier: 'med', x: 300, y: 340 },
  { id: 'au', name: 'Australia', flag: '🇦🇺', servers: '44 servers', tier: 'high', x: 830, y: 380 },
  { id: 'za', name: 'South Africa', flag: '🇿🇦', servers: '18 servers', tier: 'med', x: 545, y: 370 },
  { id: 'in', name: 'India', flag: '🇮🇳', servers: '61 servers', tier: 'med', x: 690, y: 210 },
  { id: 'gb', name: 'United Kingdom', flag: '🇬🇧', servers: '140 servers', tier: 'high', x: 480, y: 120 },
];

const FILTER_TAGS = {
  'secure-core': ['de', 'jp', 'us', 'gb'],
  'p2p': ['de', 'us', 'br', 'au'],
  'tor': ['al'],
};

// Recently connected nodes (most recent first)
const RECENTS = [
  { countryId: 'de', when: '12 minutes ago' },
  { countryId: 'us', when: '3 hours ago' },
  { countryId: 'jp', when: 'Yesterday' },
  { countryId: 'gb', when: '2 days ago' },
];

// Saved connection profiles
const PROFILES = [
  { id: 'p1', name: 'Work — Frankfurt', countryId: 'de', desc: 'Secure Core · Kill Switch on' },
  { id: 'p2', name: 'Streaming — Tokyo', countryId: 'jp', desc: 'P2P enabled · Split tunnel on' },
  { id: 'p3', name: 'Privacy Max', countryId: 'al', desc: 'Tor over PQ tunnel' },
];

let state = {
  connection: 'disconnected', // disconnected | connecting | connected
  segment: 'recents',
  filter: 'all',
  search: '',
  selected: 'fastest',
  selectedProfile: null,
};

// =====================================================================
// SESSION LOG — real event trace, feeds the Session Log view
// =====================================================================
const eventLog = [];

function addLog(message, level = 'info') {
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  eventLog.push({ ts, message, level });
  renderLog();
}

function renderLog() {
  const consoleEl = document.getElementById('logConsole');
  const countEl = document.getElementById('logCount');
  if (!consoleEl) return;
  countEl.textContent = `${eventLog.length} event${eventLog.length === 1 ? '' : 's'}`;
  // column-reverse container, so append in order and newest visually ends up on top
  consoleEl.innerHTML = eventLog.map(e => `
    <div class="log-line log-${e.level}">
      <span class="log-ts">${e.ts}</span><span class="log-tag">[${e.level.toUpperCase()}]</span>${e.message}
    </div>
  `).join('');
}

document.getElementById('logClearBtn').addEventListener('click', () => {
  eventLog.length = 0;
  renderLog();
  addLog('Session log cleared', 'info');
});

// =====================================================================
// COUNTRY LIST
// =====================================================================
function passesFilter(c) {
  if (state.filter === 'all') return true;
  const ids = FILTER_TAGS[state.filter] || [];
  return ids.includes(c.id);
}

function passesSearch(c) {
  if (!state.search) return true;
  return c.name.toLowerCase().includes(state.search.toLowerCase());
}

function countryRowHtml(c) {
  return `
    <span class="country-flag">${c.flag}</span>
    <span class="country-name">${c.name}${c.fastest ? `<span class="badge-fastest" title="Fastest">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M13 2 L4 14 H11 L10 22 L20 9 H13 Z"/></svg>
    </span>` : ''}</span>
    <span class="country-servers">${c.servers}</span>
    <span class="row-signal"><span></span><span></span><span></span></span>
  `;
}

function renderCountryList() {
  const listEl = document.getElementById('countryList');
  const filterChips = document.getElementById('filterChips');
  listEl.innerHTML = '';

  // Filter chips only make sense against the full country directory
  filterChips.style.display = state.segment === 'countries' ? 'flex' : 'none';

  if (state.segment === 'recents') {
    const items = RECENTS
      .map(r => ({ ...COUNTRIES.find(c => c.id === r.countryId), when: r.when }))
      .filter(c => c && c.name.toLowerCase().includes(state.search.toLowerCase()));

    if (items.length === 0) {
      listEl.innerHTML = emptyState(`No recent connections match “${state.search}”`);
      return;
    }
    items.forEach(c => {
      const row = document.createElement('div');
      row.className = `country-row ${c.tier}${state.selected === c.id ? ' selected' : ''}`;
      row.innerHTML = `
        <span class="country-flag">${c.flag}</span>
        <span class="country-name">${c.name}<span class="recent-time">${c.when}</span></span>
        <span class="row-signal"><span></span><span></span><span></span></span>
      `;
      row.addEventListener('click', () => selectCountry(c.id));
      listEl.appendChild(row);
    });
    return;
  }

  if (state.segment === 'profiles') {
    const items = PROFILES.filter(p => p.name.toLowerCase().includes(state.search.toLowerCase()));
    if (items.length === 0) {
      listEl.innerHTML = emptyState(`No profiles match “${state.search}”`);
      return;
    }
    items.forEach(p => {
      const c = COUNTRIES.find(x => x.id === p.countryId);
      const card = document.createElement('div');
      card.className = `profile-card${state.selectedProfile === p.id ? ' selected' : ''}`;
      card.innerHTML = `
        <div class="profile-card-top">
          <span class="profile-name">${p.name}</span>
          <span class="profile-flag">${c ? c.flag : '🌐'}</span>
        </div>
        <div class="profile-desc">${p.desc}</div>
      `;
      card.addEventListener('click', () => {
        state.selectedProfile = p.id;
        addLog(`Loaded profile "${p.name}"`, 'info');
        if (c) selectCountry(c.id); else renderCountryList();
      });
      listEl.appendChild(card);
    });
    return;
  }

  // segment === 'countries'
  const items = COUNTRIES.filter(c => passesFilter(c) && passesSearch(c));
  if (items.length === 0) {
    listEl.innerHTML = emptyState(`No locations match “${state.search}”`);
    return;
  }
  items.forEach(c => {
    const row = document.createElement('div');
    row.className = `country-row ${c.tier}${state.selected === c.id ? ' selected' : ''}`;
    row.dataset.id = c.id;
    row.innerHTML = countryRowHtml(c);
    row.addEventListener('click', () => selectCountry(c.id));
    listEl.appendChild(row);
  });
}

function emptyState(msg) {
  return `<div style="padding:20px 8px; font-size:11px; color:var(--text-tertiary); text-align:center;">${msg}</div>`;
}

function selectCountry(id) {
  state.selected = id;
  const c = COUNTRIES.find(x => x.id === id);
  document.getElementById('fastestTitle').textContent =
    c.fastest ? 'Fastest Node — Frankfurt, DE' : `Selected Node — ${c.name}`;
  renderCountryList();
  moveLatticeAnchor(c.x, c.y);
  addLog(`Selected node: ${c.name}`, 'info');
}

document.getElementById('searchInput').addEventListener('input', (e) => {
  state.search = e.target.value;
  renderCountryList();
});

document.querySelectorAll('.seg-tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.seg-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    state.segment = tab.dataset.seg;
    renderCountryList();
  });
});

document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    state.filter = chip.dataset.filter;
    renderCountryList();
  });
});

// ---- Titlebar tabs: Dashboard / Lattice Monitor / Session Log ----
function switchView(viewName) {
  document.querySelectorAll('.tbtab').forEach(t => t.classList.toggle('active', t.dataset.tab === viewName));
  document.querySelectorAll('.app-view').forEach(v => v.classList.toggle('active', v.dataset.view === viewName));
  if (viewName === 'dashboard') {
    // map-canvas has zero size while hidden, so re-anchor the lattice overlay now that it's visible again
    requestAnimationFrame(() => {
      const c = COUNTRIES.find(x => x.id === state.selected);
      if (c) moveLatticeAnchor(c.x, c.y);
    });
  }
}

document.querySelectorAll('.tbtab').forEach(tab => {
  tab.addEventListener('click', () => switchView(tab.dataset.tab));
});

// Settings gear in the right dock opens the Settings view (no titlebar tab for it,
// so we just clear titlebar highlighting and swap the visible panel)
document.querySelector('.util-tile--settings').addEventListener('click', () => {
  document.querySelectorAll('.tbtab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.app-view').forEach(v => v.classList.toggle('active', v.dataset.view === 'settings'));
  addLog('Opened Settings', 'info');
});

document.querySelectorAll('[data-setting]').forEach(toggle => {
  toggle.addEventListener('click', () => {
    toggle.classList.toggle('on');
    const isOn = toggle.classList.contains('on');
    addLog(`Setting "${toggle.dataset.setting}" turned ${isOn ? 'on' : 'off'}`, 'info');
  });
});

// =====================================================================
// WORLD MAP — stylized geometric dot-grid continents + server nodes
// =====================================================================
const svgNS = 'http://www.w3.org/2000/svg';
const worldSvg = document.getElementById('worldSvg');

// Simplified continental silhouettes as polylines (stylized, not geographic truth)
const LANDMASSES = [
  // North America
  'M120,90 L230,70 L260,110 L250,170 L200,230 L150,220 L110,180 L95,130 Z',
  // South America
  'M240,260 L300,250 L330,320 L300,420 L260,440 L230,380 L235,300 Z',
  // Europe
  'M460,80 L560,70 L580,120 L540,150 L470,140 Z',
  // Africa
  'M470,170 L580,165 L610,260 L570,400 L510,410 L470,300 L460,220 Z',
  // Asia
  'M600,60 L820,50 L900,140 L860,230 L720,240 L630,180 L590,110 Z',
  // Australia
  'M780,360 L880,355 L900,410 L840,430 L780,410 Z',
];

LANDMASSES.forEach(d => {
  const path = document.createElementNS(svgNS, 'path');
  path.setAttribute('d', d);
  path.setAttribute('class', 'world-land');
  worldSvg.appendChild(path);
});

// Background dot grid (evokes lattice/vector field of the PQ theme)
const GRID_GROUP = document.createElementNS(svgNS, 'g');
for (let x = 20; x < 1000; x += 26) {
  for (let y = 20; y < 500; y += 26) {
    const dot = document.createElementNS(svgNS, 'circle');
    dot.setAttribute('cx', x);
    dot.setAttribute('cy', y);
    dot.setAttribute('r', 0.9);
    dot.setAttribute('class', 'world-grid-dot');
    GRID_GROUP.appendChild(dot);
  }
}
worldSvg.insertBefore(GRID_GROUP, worldSvg.firstChild);

// Server nodes at each country's coordinates
COUNTRIES.forEach(c => {
  const node = document.createElementNS(svgNS, 'circle');
  node.setAttribute('cx', c.x);
  node.setAttribute('cy', c.y);
  node.setAttribute('r', 2);
  node.setAttribute('class', 'server-node pulse');
  node.style.animationDelay = `${Math.random() * 2}s`;
  worldSvg.appendChild(node);
});

// =====================================================================
// LATTICE RADAR — signature element referencing lattice-based PQC
// =====================================================================
function buildHexLattice() {
  const group = document.getElementById('latticeHex');
  const rings = document.getElementById('latticeRings');
  group.innerHTML = '';
  rings.innerHTML = '';

  const cx = 150, cy = 150;
  const hexR = 22;

  // concentric faint rings
  [40, 75, 110].forEach((r, i) => {
    const c = document.createElementNS(svgNS, 'circle');
    c.setAttribute('cx', cx); c.setAttribute('cy', cy); c.setAttribute('r', r);
    c.setAttribute('stroke-width', 0.7);
    c.setAttribute('opacity', 0.14 + i * 0.04);
    rings.appendChild(c);
  });

  // hex-lattice: rings of hexagon centers around the anchor (lattice points)
  const points = [{ x: cx, y: cy }];
  for (let ring = 1; ring <= 2; ring++) {
    for (let i = 0; i < 6; i++) {
      const angle = (Math.PI / 3) * i;
      const px = cx + Math.cos(angle) * hexR * ring * 1.6;
      const py = cy + Math.sin(angle) * hexR * ring * 1.6;
      points.push({ x: px, y: py });
    }
  }

  // connective edges (only near-neighbors, to read as a lattice mesh)
  points.forEach((p1, i) => {
    points.forEach((p2, j) => {
      if (j <= i) return;
      const dist = Math.hypot(p1.x - p2.x, p1.y - p2.y);
      if (dist < hexR * 1.8) {
        const line = document.createElementNS(svgNS, 'line');
        line.setAttribute('x1', p1.x); line.setAttribute('y1', p1.y);
        line.setAttribute('x2', p2.x); line.setAttribute('y2', p2.y);
        line.setAttribute('stroke', 'rgba(41,240,255,0.22)');
        line.setAttribute('stroke-width', 0.6);
        group.appendChild(line);
      }
    });
  });

  // lattice point nodes
  points.forEach((p, i) => {
    const dot = document.createElementNS(svgNS, 'circle');
    dot.setAttribute('cx', p.x); dot.setAttribute('cy', p.y);
    dot.setAttribute('r', i === 0 ? 0 : 1.5);
    dot.setAttribute('fill', 'rgba(41,240,255,0.5)');
    group.appendChild(dot);
  });
}
buildHexLattice();

function moveLatticeAnchor(mapX, mapY) {
  // Position the lattice radar overlay above the selected node on the map
  const radar = document.getElementById('latticeRadar');
  const canvasRect = document.getElementById('mapCanvas').getBoundingClientRect();
  const viewBoxW = 1000, viewBoxH = 520;
  const scale = Math.min(canvasRect.width / viewBoxW, canvasRect.height / viewBoxH);
  const offsetX = (canvasRect.width - viewBoxW * scale) / 2;
  const offsetY = (canvasRect.height - viewBoxH * scale) / 2;
  const px = offsetX + mapX * scale;
  const py = offsetY + mapY * scale;
  radar.style.left = `${px}px`;
  radar.style.top = `${py}px`;
}
window.addEventListener('resize', () => {
  const c = COUNTRIES.find(x => x.id === state.selected);
  if (c) moveLatticeAnchor(c.x, c.y);
});

// =====================================================================
// CONNECT / DISCONNECT FLOW
// =====================================================================
const connectBtn = document.getElementById('connectBtn');
const connectBtnLabel = document.getElementById('connectBtnLabel');
const statusShelf = document.getElementById('statusShelf');
const statusLabel = document.getElementById('statusLabel');
const statusCaption = document.getElementById('statusCaption');
const metaVirtualIp = document.getElementById('metaVirtualIp');
const metaEncryption = document.getElementById('metaEncryption');
const metaLatency = document.getElementById('metaLatency');

function setConnectionUI(mode) {
  state.connection = mode;
  connectBtn.classList.remove('connected', 'connecting');
  statusShelf.classList.remove('protected');

  if (mode === 'disconnected') {
    connectBtnLabel.textContent = 'Connect';
    statusLabel.textContent = 'UNPROTECTED';
    statusCaption.textContent = 'Traffic is not passing through the PQ tunnel';
    metaVirtualIp.textContent = '—';
    metaEncryption.textContent = 'Inactive';
    metaLatency.textContent = '—';
  } else if (mode === 'connecting') {
    connectBtn.classList.add('connecting');
    connectBtnLabel.textContent = 'Negotiating…';
    statusLabel.textContent = 'ESTABLISHING TUNNEL';
    statusCaption.textContent = 'Performing hybrid ML-KEM-1024 / X25519 key exchange';
    metaVirtualIp.textContent = 'Pending…';
    metaEncryption.textContent = 'Handshake in progress';
    metaLatency.textContent = '—';
  } else if (mode === 'connected') {
    connectBtn.classList.add('connected');
    statusShelf.classList.add('protected');
    connectBtnLabel.textContent = 'Disconnect';
    statusLabel.textContent = 'PROTECTED';
    statusCaption.textContent = 'Traffic is secured through the PQ tunnel';
    metaVirtualIp.textContent = '10.8.0.5';
    metaEncryption.textContent = 'Secured (Kyber Hybrid Matrix)';
    metaLatency.textContent = `${26 + Math.round(Math.random() * 6)}ms`;
  }
}




// render.js mein connectBtn listener:

connectBtn.addEventListener('click', async () => {
  if (state.connection === 'disconnected') {
    const c = COUNTRIES.find(x => x.id === state.selected);
    setConnectionUI('connecting');
    addLog(`Starting hybrid handshake with ${c ? c.name : 'selected node'} (107.21.77.85)…`, 'info');

    try {
      // Local Python API Call on Port 5000
      const response = await fetch('http://127.0.0.1:5000/api/v1/client/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          gateway_ip: '107.21.77.85',
          gateway_port: 8001,
          force_tunnel: true
        })
      });

      const resData = await response.json();

      if (response.ok && resData.status === 'success') {
        setConnectionUI('connected');
        handshakeCount += 1;
        const assignedIp = resData.data?.assigned_vip || '10.8.0.2';
        addLog(`Tunnel established — ML-KEM-1024 + X25519 (Virtual IP: ${assignedIp})`, 'ok');
        updateLatticeMonitor();
      } else {
        setConnectionUI('disconnected');
        addLog(`Handshake failed: ${resData.message}`, 'error');
      }
    } catch (err) {
      setConnectionUI('disconnected');
      addLog(`Connection error: Could not reach local backend agent on port 5000`, 'error');
    }

  } else if (state.connection === 'connected') {
    setConnectionUI('disconnected');
    addLog('Tunnel disconnected', 'warn');
  }
});
// =====================================================================
// LATTICE MONITOR — mock but live-updating diagnostics panel
// =====================================================================
let handshakeCount = 0;
let kemOps = 0;
let sigOps = 0;

function updateLatticeMonitor() {
  const statHandshakes = document.getElementById('statHandshakes');
  const lhStatus = document.getElementById('lhStatus');
  if (statHandshakes) statHandshakes.textContent = handshakeCount;
  if (lhStatus) lhStatus.textContent = state.connection === 'connected'
    ? `Complete — ${new Date().toLocaleTimeString('en-GB', { hour12: false })}`
    : 'No handshake yet';
}

const noiseHistory = new Array(60).fill(0);
function tickLatticeMonitor() {
  const active = state.connection === 'connected';
  if (active) {
    kemOps += Math.round(Math.random() * 3);
    sigOps += Math.round(Math.random() * 2);
  }
  const statKemOps = document.getElementById('statKemOps');
  const statSigOps = document.getElementById('statSigOps');
  if (statKemOps) statKemOps.textContent = kemOps;
  if (statSigOps) statSigOps.textContent = sigOps;

  noiseHistory.push(active ? 30 + Math.random() * 60 : Math.random() * 8);
  noiseHistory.shift();
  drawNoiseChart();
}

function drawNoiseChart() {
  const canvas = document.getElementById('noiseChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  ctx.beginPath();
  noiseHistory.forEach((v, i) => {
    const x = (i / (noiseHistory.length - 1)) * w;
    const y = h - (v / 100) * (h - 10) - 5;
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = 'rgba(41,240,255,0.85)';
  ctx.lineWidth = 1.5;
  ctx.stroke();
}

setInterval(tickLatticeMonitor, 900);

// =====================================================================
// UTILITY TOGGLES
// =====================================================================
document.querySelectorAll('.toggle[data-toggle]').forEach(toggle => {
  toggle.addEventListener('click', () => {
    toggle.classList.toggle('on');
    const key = toggle.dataset.toggle;
    const subEl = document.getElementById(`${key}Sub`);
    const isOn = toggle.classList.contains('on');
    const copy = {
      netshield: isOn ? 'Blocking ads & trackers' : 'Disabled',
      killswitch: isOn ? 'Blocks traffic if tunnel drops' : 'Disabled — traffic exposed on drop',
      portforward: isOn ? 'Forwarding port 51820' : 'Not configured',
      splittunnel: isOn ? '3 apps routed outside tunnel' : 'Disabled — all traffic tunneled',
    };
    if (subEl) subEl.textContent = copy[key];
    addLog(`${key} turned ${isOn ? 'on' : 'off'}`, 'info');
  });
});

// =====================================================================
// SPARKLINE — live throughput visualization
// =====================================================================
const spark = document.getElementById('sparkline');
const sparkCtx = spark.getContext('2d');
const throughputUp = document.getElementById('throughputUp');
const throughputDown = document.getElementById('throughputDown');

const HISTORY_LEN = 40;
let upHistory = new Array(HISTORY_LEN).fill(0);
let downHistory = new Array(HISTORY_LEN).fill(0);

function fmtRate(v) {
  if (v > 1024) return `${(v / 1024).toFixed(1)} MB/s`;
  return `${v.toFixed(1)} KB/s`;
}

function tickThroughput() {
  const active = state.connection === 'connected';
  const nextUp = active ? Math.max(0, upHistory[upHistory.length - 1] + (Math.random() - 0.5) * 40 + 10) : 0;
  const nextDown = active ? Math.max(0, downHistory[downHistory.length - 1] + (Math.random() - 0.5) * 90 + 20) : 0;
  upHistory.push(nextUp); upHistory.shift();
  downHistory.push(nextDown); downHistory.shift();
  throughputUp.textContent = fmtRate(nextUp);
  throughputDown.textContent = fmtRate(nextDown);
  drawSparkline();
}

function drawSparkline() {
  const w = spark.width, h = spark.height;
  sparkCtx.clearRect(0, 0, w, h);
  const maxVal = Math.max(...upHistory, ...downHistory, 20);

  function drawLine(history, color) {
    sparkCtx.beginPath();
    history.forEach((v, i) => {
      const x = (i / (HISTORY_LEN - 1)) * w;
      const y = h - (v / maxVal) * (h - 4) - 2;
      i === 0 ? sparkCtx.moveTo(x, y) : sparkCtx.lineTo(x, y);
    });
    sparkCtx.strokeStyle = color;
    sparkCtx.lineWidth = 1.4;
    sparkCtx.stroke();
  }

  drawLine(upHistory, 'rgba(255,61,154,0.85)');
  drawLine(downHistory, 'rgba(41,240,255,0.85)');
}

setInterval(tickThroughput, 900);

// =====================================================================
// INIT
// =====================================================================
renderCountryList();
setConnectionUI('disconnected');
requestAnimationFrame(() => {
  const c = COUNTRIES.find(x => x.id === state.selected);
  moveLatticeAnchor(c.x, c.y);
});
drawSparkline();
drawNoiseChart();
updateLatticeMonitor();
addLog('PQ Tunneling initialized', 'ok');
