/**
 * BoardView — Monday.com-style kanban board for the maintenance page.
 *
 * Features:
 * - Dark-themed swimlanes grouped by status (LIVE, ON HOLD, WAITING, COMPLETED)
 * - Color-coded priority pills (Medium=orange, High=purple, Critical=red)
 * - Color-coded type tags (Small Repair=green, Cleaning=blue, Appliances=yellow, etc.)
 * - Checkbox selection, reference numbers, dates, addresses, evidence icons
 * - Toggle between Table view and Board view
 * - All data from /api/banksia_os/maintenance/jobs
 *
 * Paste this at the end of banksia_os.html just before </script>
 */

// ── TYPES CONFIG ──
const MAINT_TYPE_COLORS = {
  'Small Repair': { bg: '#d4edda', fg: '#155724', icon: '🔧' },
  'Plumbing':     { bg: '#d1ecf1', fg: '#0c5460', icon: '🔩' },
  'Electrical':   { bg: '#fff3cd', fg: '#856404', icon: '⚡' },
  'Gas':          { bg: '#f8d7da', fg: '#721c24', icon: '🔥' },
  'Cleaning':     { bg: '#cce5ff', fg: '#004085', icon: '🧹' },
  'Appliances':   { bg: '#fff8e1', fg: '#795548', icon: '📺' },
  'Furniture':    { bg: '#e8f5e9', fg: '#2e7d32', icon: '🪑' },
  'Orders':       { bg: '#e1bee7', fg: '#4a148c', icon: '📦' },
  'Keys/Access':  { bg: '#ffe0b2', fg: '#e65100', icon: '🔑' },
  'Inspection':   { bg: '#b2ebf2', fg: '#006064', icon: '🔍' },
  'Pest Control': { bg: '#efebe9', fg: '#4e342e', icon: '🐜' },
  'Structural':   { bg: '#ffcdd2', fg: '#b71c1c', icon: '🏗️' },
};
const MAINT_DEFAULT_TYPE = { bg: '#e2e8f0', fg: '#475569', icon: '📋' };

const MAINT_PRIORITY_COLORS = {
  'Emergency':  { bg: '#dc2626', fg: '#fff' },
  'Critical':   { bg: '#dc2626', fg: '#fff' },
  'High':       { bg: '#7c3aed', fg: '#fff' },
  'Medium':     { bg: '#ea580c', fg: '#fff' },
  'Low':        { bg: '#64748b', fg: '#fff' },
};

const MAINT_STATUS_ORDER = ['LIVE', 'IN PROGRESS', 'ON HOLD', 'WAITING INVOICE', 'No Invoice Found', 'Invoice Uploaded', 'PENDING', 'ACKNOWLEDGED', 'CANCELLED', 'COMPLETED'];

// ── RENDER MAIN BOARD ──
function renderBoardView() {
  const el = document.getElementById('page-content');
  el.innerHTML = `
    <div class="board-header">
      <div class="board-filters">
        <input type="text" id="board-search" placeholder="Search jobs..." style="width:260px" oninput="debounceSearchBoard()">
        <select id="board-priority-filter" onchange="renderBoardView()">
          <option value="">All priorities</option>
          <option value="Emergency">Emergency</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>
        <select id="board-contractor-filter" onchange="renderBoardView()">
          <option value="">All contractors</option>
        </select>
        <div class="board-view-toggle">
          <button class="btn btn-ghost btn-sm active" onclick="switchMaintenanceView('board')">📋 Board</button>
          <button class="btn btn-ghost btn-sm" onclick="switchMaintenanceView('table')">📄 Table</button>
        </div>
      </div>
    </div>
    <div class="board-scroll" id="board-scroll">
      <div class="board-container" id="board-container">
        ${MAINT_STATUS_ORDER.map(s => `
          <div class="board-column" data-column="${s}">
            <div class="board-column-header" data-status="${s}">
              <span class="board-col-title">${s.replace(/_/g, ' ')}</span>
              <span class="board-col-count" id="col-count-${s.replace(/\s+/g, '_')}">0</span>
            </div>
            <div class="board-column-body" id="col-body-${s.replace(/\s+/g, '_')}">
              <div class="loading" style="padding:24px"><div class="spinner"></div></div>
            </div>
          </div>
        `).join('')}
      </div>
    </div>
  `;

  loadBoardData();
}

function loadBoardData() {
  const search = document.getElementById('board-search')?.value || '';
  const priority = document.getElementById('board-priority-filter')?.value || '';
  const contractor = document.getElementById('board-contractor-filter')?.value || '';

  let url = '/api/banksia_os/maintenance/jobs?per_page=200';
  if (search) url += '&search=' + encodeURIComponent(search);
  if (priority) url += '&priority=' + encodeURIComponent(priority);
  if (contractor) url += '&contractor=' + encodeURIComponent(contractor);

  api(url).then(res => {
    const jobs = res.data || [];

    // Populate contractor filter
    const cFilter = document.getElementById('board-contractor-filter');
    if (cFilter && !cFilter.dataset.loaded) {
      cFilter.dataset.loaded = '1';
      const contractors = [...new Set(jobs.map(j => j.contractor).filter(Boolean))].sort();
      contractors.forEach(c => {
        const opt = document.createElement('option');
        opt.value = c; opt.textContent = c;
        cFilter.appendChild(opt);
      });
    }

    // Group by status
    const grouped = {};
    MAINT_STATUS_ORDER.forEach(s => grouped[s] = []);
    jobs.forEach(j => {
      const status = (j.status || 'PENDING').toUpperCase();
      if (grouped[status]) grouped[status].push(j);
      else grouped['PENDING'].push(j);
    });

    // Render each column
    MAINT_STATUS_ORDER.forEach(status => {
      const key = status.replace(/\s+/g, '_');
      const countEl = document.getElementById(`col-count-${key}`);
      const bodyEl = document.getElementById(`col-body-${key}`);
      if (!bodyEl) return;
      const items = grouped[status] || [];
      if (countEl) countEl.textContent = items.length;

      if (items.length === 0) {
        bodyEl.innerHTML = '<div class="board-empty">No jobs</div>';
        return;
      }

      bodyEl.innerHTML = items.map(j => `
        <div class="board-card" onclick="openMaintenanceJob(${j.id})" data-job-id="${j.id}">
          <div class="board-card-check">
            <input type="checkbox" onclick="event.stopPropagation()">
          </div>
          <div class="board-card-body">
            <div class="board-card-ref">${escHtml(j.reference || '#N/A')}</div>
            <div class="board-card-title">${escHtml(j.title || '')}</div>
            <div class="board-card-meta">
              ${j.when_raised ? `<span class="board-meta-item">📅 ${fmtDate(j.when_raised)}</span>` : ''}
              ${j.start_date ? `<span class="board-meta-item">🗓️ ${fmtDate(j.start_date)}</span>` : ''}
            </div>
            <div class="board-card-address">${escHtml(j.address || j.property_name || '')}</div>
          </div>
          <div class="board-card-tags">
            ${j.priority ? `<span class="board-pill priority" style="background:${(MAINT_PRIORITY_COLORS[j.priority]||{}).bg||'#64748b'};color:${(MAINT_PRIORITY_COLORS[j.priority]||{}).fg||'#fff'}">${j.priority}</span>` : ''}
            ${j.type ? (() => { const tc = MAINT_TYPE_COLORS[j.type] || MAINT_DEFAULT_TYPE; return `<span class="board-pill type" style="background:${tc.bg};color:${tc.fg}">${tc.icon} ${j.type}</span>`; })() : ''}
            ${j.bill_ll ? '<span class="board-pill bill-ll" style="background:#fef3c7;color:#92400e">💰 LL</span>' : ''}
          </div>
          <div class="board-card-evidence">
            ${j.photo_paths ? `<span class="board-evidence-icon" title="Has photos">📷</span>` : ''}
            ${j.invoice_paths ? `<span class="board-evidence-icon" title="Has invoices">📄</span>` : ''}
            ${j.order_count > 0 ? `<span class="board-evidence-icon" title="${j.order_count} orders">📦${j.order_count}</span>` : ''}
          </div>
          ${j.contractor ? `<div class="board-card-footer">👤 ${escHtml(j.contractor)}</div>` : ''}
        </div>
      `).join('');
    });
  }).catch(e => {
    document.getElementById('board-container').innerHTML = `<div class="empty-state"><div class="icon">⚠</div><h3>Failed to load</h3><p>${escHtml(e.message)}</p></div>`;
  });
}

let boardSearchTimer = null;
function debounceSearchBoard() {
  clearTimeout(boardSearchTimer);
  boardSearchTimer = setTimeout(loadBoardData, 300);
}

function switchMaintenanceView(view) {
  // Update the toggle buttons
  document.querySelectorAll('.board-view-toggle button').forEach(b => {
    b.classList.toggle('active', b.textContent.toLowerCase().includes(view));
  });
  if (view === 'board') {
    renderBoardView();
  } else {
    renderMaintenance();
  }
}

// Inject board CSS into <style> block
(function injectBoardCSS() {
  const css = `
/* ── BOARD VIEW (Monday.com style) ── */
.board-header{padding:0 0 16px 0}
.board-filters{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.board-view-toggle{display:flex;background:#f1f5f9;border-radius:8px;padding:3px;margin-left:auto}
.board-view-toggle button{border:none;border-radius:6px;font-size:11px;font-weight:500;cursor:pointer;}
.board-scroll{overflow-x:auto;padding-bottom:16px;margin:-4px}
.board-container{display:flex;gap:16px;min-width:max-content;padding:4px}
.board-column{min-width:320px;max-width:380px;flex-shrink:0}
.board-column-header{display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-radius:10px 10px 0 0;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:0.5px}
.board-column-header[data-status="LIVE"]{background:#000;color:#60a5fa}
.board-column-header[data-status="IN PROGRESS"]{background:#000;color:#34d399}
.board-column-header[data-status="ON HOLD"]{background:#000;color:#fb923c}
.board-column-header[data-status="COMPLETED"]{background:#000;color:#94a3b8}
.board-column-header[data-status="WAITING INVOICE"]{background:#000;color:#fbbf24}
.board-column-header[data-status="PENDING"]{background:#000;color:#94a3b8}
.board-column-header[data-status="ACKNOWLEDGED"]{background:#000;color:#818cf8}
.board-column-header[data-status="CANCELLED"]{background:#000;color:#fca5a5}
.board-column-header[data-status="No Invoice Found"]{background:#000;color:#fb923c}
.board-column-header[data-status="Invoice Uploaded"]{background:#000;color:#34d399}
.board-col-count{background:rgba(255,255,255,.1);padding:2px 10px;border-radius:8px;font-size:11px}
.board-column-body{background:#1a1d23;border-radius:0 0 10px 10px;padding:8px;min-height:200px;max-height:calc(100vh - 320px);overflow-y:auto}
.board-empty{padding:32px;text-align:center;color:#4a5568;font-size:13px}
.board-card{background:#23272e;border:1px solid #2d3139;border-radius:10px;padding:14px;margin-bottom:8px;cursor:pointer;transition:all .15s;display:grid;grid-template-columns:auto 1fr;gap:10px;position:relative}
.board-card:hover{border-color:#4a5568;background:#2d3139;transform:translateY(-1px)}
.board-card-check{padding-top:2px}
.board-card-check input{width:16px;height:16px;cursor:pointer;accent-color:#6366f1}
.board-card-body{min-width:0}
.board-card-ref{font-size:10px;color:#6b7280;font-weight:500;margin-bottom:2px}
.board-card-title{font-size:13px;font-weight:600;color:#e2e8f0;margin-bottom:4px;line-height:1.3}
.board-card-meta{display:flex;gap:10px;font-size:10px;color:#6b7280;margin-bottom:4px}
.board-meta-item{white-space:nowrap}
.board-card-address{font-size:11px;color:#9ca3af;margin-bottom:6px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.board-card-tags{grid-column:1/-1;display:flex;gap:6px;flex-wrap:wrap;margin-top:2px}
.board-pill{display:inline-flex;align-items:center;gap:3px;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:500;line-height:1.3}
.board-card-evidence{position:absolute;top:14px;right:14px;display:flex;gap:4px}
.board-evidence-icon{font-size:12px;opacity:.6}
.board-card-footer{grid-column:1/-1;font-size:10px;color:#6b7280;padding-top:6px;border-top:1px solid #2d3139;margin-top:2px}
`;
  const style = document.createElement('style');
  style.textContent = css;
  document.head.appendChild(style);
})();
