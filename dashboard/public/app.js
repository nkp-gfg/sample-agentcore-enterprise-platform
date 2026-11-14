(() => {
  'use strict';

  /* ── CONFIG ─────────────────────────────────────────────────────────────── */
  const POLL_INTERVAL = 10000;      // monitor.py rewrites status.json every 15s
  const STALE_AFTER = 60;           // seconds without a fresh timestamp → warn
  const LAYERS = [
    { id: 'foundation',    name: 'Foundation',    stacks: ['networking', 'security'] },
    { id: 'identity',      name: 'Identity',      stacks: ['auth', 'identity'] },
    { id: 'service',       name: 'Service',       stacks: ['gateway', 'memory'] },
    { id: 'runtime',       name: 'Runtime',       stacks: ['runtime-orchestrator', 'runtime-code-agent', 'runtime-research-agent'] },
    { id: 'observability', name: 'Observability', stacks: ['observability'] }
  ];
  // How an out-of-scope stack is switched on. Keys mirror platform.yaml.
  const ENABLE_HINT = {
    'networking': 'networking.enabled: true',
    'security': 'security.enabled: true',
    'runtime-code-agent': 'agents.a2a: true',
    'runtime-research-agent': 'agents.a2a: true'
  };
  const STATE_LABEL = {
    'deployed': 'Deployed', 'in-progress': 'Deploying', 'failed': 'Failed',
    'not-deployed': 'Not deployed', 'not-applicable': 'Not in scope'
  };
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const ICON_SHAPES = {
    deployed: [
      ['circle', { cx: '8', cy: '8', r: '7' }],
      ['path', { d: 'M4.5 8.3l2.4 2.4 4.6-5' }]
    ],
    failed: [
      ['circle', { cx: '8', cy: '8', r: '7' }],
      ['path', { d: 'M5.5 5.5l5 5M10.5 5.5l-5 5' }]
    ],
    'in-progress': [
      ['path', { d: 'M8 1a7 7 0 1 1-7 7' }]
    ],
    'not-deployed': [
      ['circle', { cx: '8', cy: '8', r: '7', 'stroke-dasharray': '3 2.2' }]
    ],
    'not-applicable': [
      ['circle', { cx: '8', cy: '8', r: '7' }],
      ['path', { d: 'M5 8h6' }]
    ],
    warning: [
      ['path', { d: 'M8 2l6.5 11.5H1.5z' }],
      ['path', { d: 'M8 6.5v3M8 12h.01' }]
    ],
    info: [
      ['circle', { cx: '8', cy: '8', r: '7' }],
      ['path', { d: 'M8 7.5v4M8 5h.01' }]
    ]
  };
  // Defense in depth for old or hand-written status files. monitor.py applies
  // the same allow-list before writing JSON; the browser repeats it before any
  // output can reach the DOM or graph.js.
  const SAFE_OUTPUT_KEYS = new Set([
    'VpcId', 'PrivateSubnetIds', 'RuntimeSecurityGroupId', 'KmsKeyArn',
    'UserPoolId', 'UserPoolArn', 'IssuerUrl', 'DiscoveryUrl', 'AppClientId',
    'WebClientId', 'M2MClientId', 'DomainUrl', 'IdPType', 'IdPMode',
    'GatewayCredentialProviderName', 'GoogleProviderArn', 'GithubProviderArn',
    'NotionProviderArn', 'GatewayUrl', 'GatewayArn', 'GatewayId', 'MemoryId',
    'MemoryArn', 'RuntimeArn', 'RuntimeId', 'SourceHash', 'ImageUri',
    'SecurityAlertsTopicArn', 'MonitoredResources',
    // HR assistant outputs — reviewed non-secret. The master-secret NAME is
    // not listed here (the test allow-list refuses any key containing
    // "secret"); operators find it in the Parameters tab under
    // `use-cases/hr-data/secret-name`.
    'ClusterArn', 'DatabaseName', 'CheckpointDatabase',
    'FunctionArn', 'KillSwitchParameter',
    'Function-hr-ops', 'Function-hr-payroll', 'Function-hr-finance'
  ]);
  const SAFE_PARAMETER_KEYS = new Set([
    'auth/mode', 'auth/issuer-url', 'auth/user-pool-id', 'auth/app-client-id',
    'auth/web-client-id', 'auth/m2m-client-id', 'auth/m2m-scope', 'gateway/url',
    'identity/gateway-credential-provider-name', 'identity/google-provider-arn',
    'identity/github-provider-arn', 'identity/notion-provider-arn',
    'memory/memory-id', 'memory/memory-arn', 'networking/vpc-id',
    'networking/private-subnet-ids', 'networking/runtime-security-group-id',
    'runtimes/orchestrator/arn', 'runtimes/orchestrator/id',
    'runtimes/code-agent/arn', 'runtimes/code-agent/id',
    'runtimes/research-agent/arn', 'runtimes/research-agent/id',
    // HR published interface (docs/hr/modules.md § SSM interface).
    'use-cases/hr-data/endpoint', 'use-cases/hr-data/secret-name',
    'use-cases/hr-data/database-name', 'use-cases/hr-data/checkpoint-database',
    'use-cases/hr-identity/function-arn', 'use-cases/hr-tools/enabled'
  ]);
  const PAGE_META = {
    overview: ['Overview', 'Deployment status', 'The deployment contract and current CloudFormation state.'],
    architecture: ['Architecture', 'AgentCore X-Ray', 'Inspect the services and relationships behind the customer-facing agent.'],
    parameters: ['Parameters', 'Published parameters', 'The non-secret SSM interface consumed by agents and use cases.'],
    agents: ['Agents', 'Deployed agents', 'Customer-testable runtimes already present in this footprint.'],
    playground: ['Playground', 'Agent playground', 'Run controlled tests against an existing deployed runtime.']
  };

  let lastStatus = null;
  let selectedKey = null;
  let returnFocusTo = null;
  let sessionToken = '';
  let initialTab = '';

  function consumeHashToken() {
    const rawHash = window.location.hash ? window.location.hash.slice(1) : '';
    if (!rawHash) return;
    if (rawHash.includes('token=')) {
      const params = new URLSearchParams(rawHash);
      const token = params.get('token');
      if (token) sessionToken = token.trim();
      const tab = params.get('tab');
      if (tab) initialTab = tab;
      history.replaceState(null, '', window.location.pathname + window.location.search);
    } else {
      initialTab = rawHash;
    }
  }

  /* ── HELPERS ────────────────────────────────────────────────────────────── */
  const $ = id => document.getElementById(id);
  function el(tag, className, ...children) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    children.forEach(child => {
      if (child === null || child === undefined || child === false) return;
      node.appendChild(typeof child === 'object' ? child : document.createTextNode(String(child)));
    });
    return node;
  }
  function relativeTime(iso) {
    if (!iso) return '—';
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 5) return 'just now';
    if (diff < 60) return Math.floor(diff) + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }
  function ageSeconds(iso) { return iso ? (Date.now() - new Date(iso).getTime()) / 1000 : Infinity; }
  function svgIcon(kind) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    (ICON_SHAPES[kind] || []).forEach(([tag, attrs]) => {
      const shape = document.createElementNS(SVG_NS, tag);
      Object.entries(attrs).forEach(([k, v]) => shape.setAttribute(k, v));
      svg.appendChild(shape);
    });
    return svg;
  }
  function indicator(state, label, raw) {
    const frag = document.createDocumentFragment();
    const text = label ?? STATE_LABEL[state] ?? state;
    frag.appendChild(el('span', `si si--${state}`, svgIcon(state), el('span', '', text)));
    if (raw) frag.appendChild(el('span', 'si-raw', raw));
    return frag;
  }
  function teamBadge(team) {
    return team ? el('span', `badge badge--${team}`, team) : el('span', 'badge', '—');
  }
  function moduleBadge(m) {
    return m ? el('span', 'badge', `Module ${m}`) : document.createTextNode('—');
  }
  function valueCell(value) {
    return el('div', 'val-cell', el('span', 'val', value ?? ''));
  }
  function sanitizeStatus(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('status.json is not an object');
    }
    const safe = { ...data, stacks: {}, ssm_parameters: {} };
    const stacks = data.stacks && typeof data.stacks === 'object' && !Array.isArray(data.stacks)
      ? data.stacks : {};
    Object.entries(stacks).forEach(([name, stack]) => {
      if (!stack || typeof stack !== 'object' || Array.isArray(stack)) return;
      const outputs = stack.outputs && typeof stack.outputs === 'object' && !Array.isArray(stack.outputs)
        ? stack.outputs : {};
      const safeOutputs = {};
      Object.entries(outputs).forEach(([key, value]) => {
        if (SAFE_OUTPUT_KEYS.has(key)) safeOutputs[key] = value;
      });
      safe.stacks[name] = { ...stack, outputs: safeOutputs };
    });
    const params = data.ssm_parameters && typeof data.ssm_parameters === 'object' && !Array.isArray(data.ssm_parameters)
      ? data.ssm_parameters : {};
    Object.entries(params).forEach(([key, value]) => {
      if (SAFE_PARAMETER_KEYS.has(key)) safe.ssm_parameters[key] = value;
    });
    return safe;
  }

  // Classification belongs to monitor.py, which emits `state` per stack; this
  // is the fallback for a status.json written before that field existed. The two
  // implementations disagreeing is exactly the bug this shape removes, so keep
  // the rules here identical to monitor.classify().
  function statusClass(stack) {
    const s = typeof stack === 'string' ? stack : stack?.status;
    if (typeof stack === 'object' && stack?.state) return stack.state;
    if (!s) return 'not-deployed';
    const l = s.toLowerCase().replace(/[_ ]/g, '-');
    // Order matters: NOT_DEPLOYED contains "deployed" and ROLLBACK_COMPLETE
    // contains "complete", so check the negative/failed states first.
    if (l === 'not-deployed' || l.includes('delete-complete')) return 'not-deployed';
    if (l === 'not-applicable') return 'not-applicable';
    if (l.includes('fail') || l.includes('rollback') || l.includes('error')) return 'failed';
    if (l.includes('progress') || l.includes('pending')) return 'in-progress';
    if (l.includes('complete')) return 'deployed';
    return 'not-deployed';
  }

  /* ── TABS ───────────────────────────────────────────────────────────────── */
  function switchTab(tab, viaUser) {
    document.querySelectorAll('.tab-content').forEach(elNode => elNode.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(elNode => {
      elNode.setAttribute('aria-selected', 'false');
      elNode.tabIndex = -1;
    });
    document.getElementById('tab-' + tab).classList.add('active');
    const btn = document.getElementById('tabbtn-' + tab);
    btn.setAttribute('aria-selected', 'true');
    btn.tabIndex = 0;
    const meta = PAGE_META[tab] || PAGE_META.overview;
    $('pageCrumb').textContent = meta[0];
    $('pageHeading').textContent = meta[1];
    $('pageSummary').textContent = meta[2];
    if (viaUser) btn.focus({ preventScroll: true });
    if (window.matchMedia('(max-width: 820px)').matches) {
      btn.scrollIntoView({ block: 'nearest', inline: 'nearest' });
    }
    history.replaceState(null, '', '#' + tab);
    closeDrawer();
    if (window.EbaConsole) window.EbaConsole.activate(tab);

    // Mount only while visible so the interactive X-Ray does not retain document
    // listeners or a hidden inspection sheet.
    if (tab === 'architecture' && window.ArchGraph) {
      window.ArchGraph.mount(document.getElementById('archFlow'));
      if (lastStatus) window.ArchGraph.update(lastStatus);
    } else if (window.ArchGraph) {
      window.ArchGraph.destroy();   // drop listeners + DOM while the tab is off-screen
    }
    fetchStatus();
  }
  document.querySelector('.tabs').addEventListener('click', e => {
    const b = e.target.closest('[data-tab]');
    if (b) switchTab(b.dataset.tab, true);
  });
  document.querySelector('.tabs').addEventListener('keydown', e => {
    if (!['ArrowRight', 'ArrowLeft', 'ArrowDown', 'ArrowUp'].includes(e.key)) return;
    e.preventDefault();
    const tabs = [...document.querySelectorAll('.tab')];
    const i = tabs.findIndex(t => t.getAttribute('aria-selected') === 'true');
    const forward = e.key === 'ArrowRight' || e.key === 'ArrowDown';
    const next = tabs[(i + (forward ? 1 : tabs.length - 1)) % tabs.length];
    switchTab(next.dataset.tab, true);
  });

  /* ── LIVE INDICATOR + BANNERS ───────────────────────────────────────────── */
  function setLive(state, text) {
    const liveEl = $('live');
    liveEl.dataset.state = state;
    $('liveText').textContent = text;
  }
  function renderBanner(data) {
    const s = (data && data.summary) || {};
    const alerts = [];
    if (s.failed > 0) {
      const count = Number(s.failed);
      const body = el(
        'div',
        '',
        el('b', '', `${count} stack${count > 1 ? 's' : ''} failed.`),
        ' Open the row for the CloudFormation status, then check the stack events in the console.'
      );
      const alert = el('div', 'alert alert--error', svgIcon('failed'), body);
      alert.setAttribute('role', 'alert');
      alerts.push(alert);
    }
    if (s.in_progress > 0) {
      const count = Number(s.in_progress);
      const body = el(
        'div',
        '',
        el('b', '', 'Deployment in progress.'),
        ` ${count} stack${count > 1 ? 's are' : ' is'} being created or updated.`
      );
      const alert = el('div', 'alert alert--info', svgIcon('in-progress'), body);
      alert.setAttribute('role', 'status');
      alerts.push(alert);
    }
    $('banner').replaceChildren(...alerts);
  }
  function renderContext(data) {
    const meta = data.metadata || data;
    const dep = data.deployment || {};
    $('infoProject').textContent = meta.project || meta.projectName || '—';
    $('infoEnv').textContent = meta.environment || meta.env || '—';
    $('infoRegion').textContent = meta.region || '—';
    $('infoAccount').textContent = meta.accountId || meta.account || '—';
    $('infoStrategy').textContent = (dep.strategy || 'centralized') + (dep.role ? ' · ' + dep.role + ' side' : '');
    $('infoPattern').textContent = data.migration_runtime ? 'migration runtime' : (data.agent_pattern || '—');
    $('deploymentMode').textContent = (data.deployment_mode === 'production' ? 'Production' : 'Workshop') + ' mode';
    $('ssmPrefix').textContent = `/${meta.project || 'project'}/${meta.environment || 'env'}/`;
  }
  function showAuthRequired(errorMessage) {
    $('authGate').hidden = false;
    const errEl = $('authGateError');
    if (errorMessage) {
      errEl.textContent = errorMessage;
      errEl.hidden = false;
    } else {
      errEl.textContent = '';
      errEl.hidden = true;
    }
    $('stateConnecting').hidden = true;
    $('stateOnline').hidden = true;
    $('stateOffline').hidden = true;
    document.querySelectorAll('.arch-online').forEach(elNode => { elNode.hidden = true; });
    $('archOffline').hidden = true;
    $('banner').replaceChildren();
    $('kpis').replaceChildren();
    $('stackRows').replaceChildren();
    renderParameters({ ssm_parameters: {} });
    if (window.EbaConsole) window.EbaConsole.update(null);
    closeDrawer();
  }
  function hideAuthRequired() {
    $('authGate').hidden = true;
    $('authGateError').textContent = '';
    $('authGateError').hidden = true;
  }
  function showUnavailable(title, message, data) {
    hideAuthRequired();
    if (data) renderContext(data);
    $('stateConnecting').hidden = true;
    $('stateOnline').hidden = true;
    $('stateOffline').hidden = false;
    $('offlineTitle').textContent = title;
    $('offlineMessage').textContent = message;
    document.querySelectorAll('.arch-online').forEach(elNode => { elNode.hidden = true; });
    $('archOffline').hidden = false;
    $('archOfflineTitle').textContent = title;
    $('archOfflineMessage').textContent = message;
    const alert = el(
      'div',
      'alert alert--error',
      svgIcon('warning'),
      el('div', '', el('b', '', `${title}.`), ' ', message)
    );
    alert.setAttribute('role', 'alert');
    $('banner').replaceChildren(alert);
    $('kpis').replaceChildren();
    $('stackRows').replaceChildren();
    renderParameters({ ssm_parameters: {} });
    if (window.EbaConsole) window.EbaConsole.update(null);
    closeDrawer();
    if (window.ArchGraph) {
      window.ArchGraph.update({
        project: data?.project || '',
        environment: data?.environment || '',
        deployment: data?.deployment || {},
        stacks: {},
        summary: {}
      });
    }
  }

  /* ── OVERVIEW ───────────────────────────────────────────────────────────── */
  function render(data) {
    hideAuthRequired();
    $('stateConnecting').hidden = true;
    $('stateOnline').hidden = false;
    $('stateOffline').hidden = true;
    renderContext(data);

    // Stacks — monitor.py keys by full stack name ({project}-{env}-{short});
    // LAYERS use short names, so resolve each short name by suffix.
    const stacks = data.stacks || {};
    const allNames = Object.keys(stacks);
    const bySuffix = short => stacks[allNames.find(n => n.endsWith('-' + short)) || short];

    // Denominator = what this configuration actually promises (the deployment
    // contract, via monitor.py) — never a fixed floor.
    const summary = data.summary || {};
    const counts = { deployed: 0, 'in-progress': 0, failed: 0, 'not-deployed': 0, 'not-applicable': 0 };
    allNames.forEach(name => { const cls = statusClass(stacks[name]); counts[cls] = (counts[cls] || 0) + 1; });
    const total = summary.total_stacks ?? (allNames.length - counts['not-applicable']);
    const resources = summary.total_resources ?? allNames.reduce((n, k) => n + (Array.isArray(stacks[k].resources) ? stacks[k].resources.length : 0), 0);
    const pct = total ? Math.round(100 * counts.deployed / total) : 0;

    $('kpis').replaceChildren(
      kpi('Deployed', counts.deployed, `${pct}% of the promised footprint`,
          counts.deployed === total && total > 0 ? 'ok' : (counts.failed ? 'err' : ''), pct, `/ ${total}`),
      kpi('Deploying', counts['in-progress'], counts['in-progress'] ? 'CloudFormation is working' : 'nothing in flight',
          counts['in-progress'] ? 'info' : ''),
      kpi('Failed', counts.failed, counts.failed ? 'needs attention' : 'no failed or rolled-back stacks',
          counts.failed ? 'err' : ''),
      kpi('Not deployed', counts['not-deployed'], counts['not-deployed'] ? 'in scope, not there yet' : 'everything in scope exists'),
      kpi('Resources', resources, 'CloudFormation resources across all stacks'),
      kpi('Not in scope', counts['not-applicable'], 'disabled for this profile')
    );

    // Main table: in-scope stacks grouped by layer, in deployment order.
    const rows = [];
    const scope = [];
    LAYERS.forEach(layer => {
      const inScope = layer.stacks.map(k => [k, bySuffix(k) || {}]).filter(([, s]) => statusClass(s) !== 'not-applicable');
      layer.stacks.forEach(k => { const s = bySuffix(k) || {}; if (statusClass(s) === 'not-applicable') scope.push([k, s, layer]); });
      if (!inScope.length) return;
      const groupHeader = el('th', '', layer.name);
      groupHeader.colSpan = 6;
      rows.push(el('tr', 'group', groupHeader));
      inScope.forEach(([key, s]) => {
        const cls = statusClass(s);
        const outputs = Object.keys(s.outputs || {}).filter(k => !k.startsWith('ExportsOutput'));
        const res = Array.isArray(s.resources) ? s.resources.length : 0;
        const fullKey = allNames.find(n => n.endsWith('-' + key)) || key;
        const row = el('tr', 'row');
        row.tabIndex = 0;
        row.setAttribute('role', 'button');
        row.dataset.key = fullKey;
        row.setAttribute('aria-selected', String(fullKey === selectedKey));

        const nameCell = el('td', '', el('div', 'stack-name', key), el('div', 'stack-desc', s.description || ''));
        const statusCell = el('td', '', indicator(cls, null, cls === 'deployed' ? '' : s.status));
        const moduleCell = el('td', '', moduleBadge(s.module));
        const teamCell = el('td', '', teamBadge(s.team));
        const resCell = el('td', 'num', res || '—');
        const outCell = el('td', 'num');
        if (outputs.length) {
          const btn = el('button', 'link-btn', outputs.length);
          btn.type = 'button';
          btn.dataset.key = fullKey;
          outCell.appendChild(btn);
        } else {
          outCell.textContent = '—';
        }
        row.append(nameCell, statusCell, moduleCell, teamCell, resCell, outCell);
        rows.push(row);
      });
    });
    $('stackRows').replaceChildren(...rows);
    $('stackCount').textContent = total;

    $('scopeBox').hidden = !scope.length;
    $('scopeCount').textContent = scope.length;
    $('scopeRows').replaceChildren(
      ...scope.map(([key, s, layer]) =>
        el(
          'tr',
          'muted',
          el('td', '', el('div', 'stack-name', key), el('div', 'stack-desc', s.description || '')),
          el('td', '', layer.name),
          el('td', '', moduleBadge(s.module)),
          el('td', '', teamBadge(s.team)),
          el('td', '', el('code', '', ENABLE_HINT[key] || 'see platform.yaml'))
        )
      )
    );

    renderParameters(data);
    if (window.EbaConsole) window.EbaConsole.update(data);
    if (selectedKey && stacks[selectedKey]) fillDrawer(selectedKey, stacks[selectedKey]);
  }
  function kpi(label, value, sub, tone, pct, smallText) {
    const card = el('div', 'kpi');
    card.dataset.tone = tone || '';
    card.appendChild(el('div', 'kpi-label', label));
    const valueNode = el('div', 'kpi-value num', String(value ?? ''));
    if (smallText !== undefined) valueNode.appendChild(el('small', '', smallText));
    card.appendChild(valueNode);
    card.appendChild(el('div', 'kpi-sub', sub));
    if (pct !== undefined) {
      const bar = el('div', 'bar');
      bar.dataset.tone = tone || '';
      const fill = el('span');
      const clamped = Math.max(0, Math.min(100, Number(pct) || 0));
      fill.style.width = `${clamped}%`;
      bar.appendChild(fill);
      card.appendChild(bar);
    }
    return card;
  }

  /* ── PARAMETERS ─────────────────────────────────────────────────────────── */
  function renderParameters(data) {
    const params = data.ssm_parameters || {};
    const keys = Object.keys(params).sort();
    const q = ($('ssmFilter').value || '').toLowerCase();
    const shown = keys.filter(k => !q || k.toLowerCase().includes(q) || String(params[k]).toLowerCase().includes(q));
    $('ssmCount').textContent = keys.length;
    if (shown.length) {
      $('ssmBody').replaceChildren(
        ...shown.map(k => el('tr', '', el('td', '', el('code', '', k)), el('td', '', valueCell(params[k]))))
      );
    } else {
      const td = el(
        'td',
        '',
        keys.length
          ? 'No parameter matches the filter.'
          : 'No parameters published yet — they appear after the first stack deploys.'
      );
      td.colSpan = 2;
      td.style.color = 'var(--ink-3)';
      td.style.padding = '24px 20px';
      $('ssmBody').replaceChildren(el('tr', '', td));
    }
  }
  $('ssmFilter').addEventListener('input', () => { if (lastStatus) renderParameters(lastStatus); });

  /* ── DRAWER ─────────────────────────────────────────────────────────────── */
  function openDrawer(key, from) {
    const s = lastStatus && lastStatus.stacks && lastStatus.stacks[key];
    if (!s) return;
    selectedKey = key;
    returnFocusTo = from || null;
    fillDrawer(key, s);
    $('drawer').hidden = false;
    document.querySelectorAll('tr.row').forEach(r => r.setAttribute('aria-selected', String(r.dataset.key === key)));
    $('drawerClose').focus();
  }
  function closeDrawer() {
    if ($('drawer').hidden) return;
    $('drawer').hidden = true;
    selectedKey = null;
    document.querySelectorAll('tr.row[aria-selected="true"]').forEach(r => r.setAttribute('aria-selected', 'false'));
    if (returnFocusTo && document.body.contains(returnFocusTo)) returnFocusTo.focus();
  }
  function fillDrawer(key, s) {
    const cls = statusClass(s);
    $('drawerTitle').textContent = key;
    $('drawerStatus').replaceChildren(indicator(cls, null, s.status));
    const outputs = s.outputs || {};
    const shown = Object.keys(outputs).filter(k => !k.startsWith('ExportsOutput')).sort();
    const hiddenExports = Object.keys(outputs).length - shown.length;
    const res = Array.isArray(s.resources) ? s.resources : [];
    const byType = {};
    res.forEach(r => { byType[r.type] = (byType[r.type] || 0) + 1; });
    const topTypes = Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 12);

    const nodes = [];
    if (s.description) nodes.push(el('p', 'desc', s.description));

    nodes.push(el('h3', '', 'Details'));
    nodes.push(
      el(
        'dl',
        'grid2',
        el('div', '', el('dt', '', 'Layer'), el('dd', '', s.layer || '—')),
        el('div', '', el('dt', '', 'Module'), el('dd', '', s.module ? 'Module ' + s.module : '—')),
        el('div', '', el('dt', '', 'Team'), el('dd', '', teamBadge(s.team))),
        el('div', '', el('dt', '', 'Resources'), el('dd', 'num', res.length))
      )
    );

    nodes.push(el('h3', '', 'Outputs', el('span', 'count-pill', shown.length)));
    if (shown.length) {
      const tbody = el(
        'tbody',
        '',
        ...shown.map(k => {
          const keyCell = el('td', '', el('code', '', k));
          keyCell.style.width = '38%';
          return el('tr', '', keyCell, el('td', '', valueCell(outputs[k])));
        })
      );
      nodes.push(el('table', '', tbody));
    } else {
      nodes.push(el('p', 'more', 'No reviewed public outputs.'));
    }
    if (hiddenExports) {
      nodes.push(el('p', 'more', `${hiddenExports} CDK cross-stack export${hiddenExports > 1 ? 's' : ''} hidden.`));
    }

    nodes.push(el('h3', '', 'Resources by type'));
    if (topTypes.length) {
      const tbody = el(
        'tbody',
        '',
        ...topTypes.map(([t, n]) => {
          const countCell = el('td', 'num', n);
          countCell.style.width = '3em';
          return el('tr', '', el('td', '', el('span', 'res-type', t)), countCell);
        })
      );
      nodes.push(el('table', '', tbody));
    } else {
      nodes.push(el('p', 'more', 'No resources yet.'));
    }
    if (Object.keys(byType).length > topTypes.length) {
      nodes.push(el('p', 'more', `+${Object.keys(byType).length - topTypes.length} more types`));
    }

    $('drawerBody').replaceChildren(...nodes);
  }
  $('drawerClose').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });
  $('stackRows').addEventListener('click', e => {
    const row = e.target.closest('[data-key]');
    if (row) openDrawer(row.dataset.key, row.closest('tr'));
  });
  $('stackRows').addEventListener('keydown', e => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('tr.row')) { e.preventDefault(); openDrawer(e.target.dataset.key, e.target); }
  });
  document.addEventListener('click', e => {
    // Outside click closes the drawer; clicks inside it or on a row do not.
    if (!$('drawer').hidden && !e.target.closest('#drawer') && !e.target.closest('[data-key]')) closeDrawer();
  });

  /* ── ARCHITECTURE ───────────────────────────────────────────────────────── */
  /* The graph owns its own drawing; this only feeds it and captions the header. */
  function renderArchitecture(data) {
    document.querySelectorAll('.arch-online').forEach(elNode => { elNode.hidden = false; });
    $('archOffline').hidden = true;
    const s = data.summary || {};
    const dep = data.deployment || {};
    const role = dep.role ? ' · this account is the ' + dep.role + ' side' : '';
    $('archSummary').replaceChildren(
      el('b', 'num', `${s.deployed ?? 0}/${s.total_stacks ?? 0}`),
      ' deployed · ',
      el('span', 'num', s.total_resources ?? 0),
      ' resources',
      el('br'),
      `${dep.strategy || 'centralized'}${role}`
    );
    if (window.ArchGraph) window.ArchGraph.update(data);
  }

  /* ── FETCH ──────────────────────────────────────────────────────────────── */
  async function fetchStatus() {
    if (document.hidden) return;          // nothing to draw for a background tab
    try {
      const fetchOptions = sessionToken
        ? { cache: 'no-store', headers: { Authorization: `Bearer ${sessionToken}` } }
        : { cache: 'no-store' };
      const res = await fetch('status.json?t=' + Date.now(), fetchOptions);
      if (res.status === 401) {
        lastStatus = null;
        showAuthRequired(
          sessionToken
            ? 'Invalid session token. Copy the current token printed by dashboard/server.py.'
            : ''
        );
        setLive('offline', 'Session token required');
        return;
      }
      if (!res.ok) throw new Error(res.status);
      const data = sanitizeStatus(await res.json());
      if (data.poll_error || data.available === false) {
        lastStatus = null;
        const problem = data.poll_error || {};
        showUnavailable(
          'AWS poll failed',
          problem.message || 'The monitor could not read current AWS status. Check its terminal for details.',
          data
        );
        setLive('offline', 'AWS poll failed');
        return;
      }
      if (!data.timestamp || !data.summary || !data.stacks) {
        throw new Error('status.json is incomplete');
      }
      lastStatus = data;
      render(data);
      renderArchitecture(data);
      tickLive();
    } catch (e) {
      lastStatus = null;
      showUnavailable(
        'Poller unavailable',
        'Current status.json could not be read. Start monitor.py or check the local web server.',
        null
      );
      setLive('offline', 'Poller not running');
    }
  }
  /* Freshness is recomputed every second, so a dead poller cannot keep showing
     "just now" with a green dot — the exact failure a status page must not have. */
  function tickLive() {
    if (!lastStatus) return;
    const age = ageSeconds(lastStatus.timestamp);
    if (!Number.isFinite(age) || age < -5) {
      showUnavailable(
        'Status timestamp is invalid',
        'status.json does not contain a plausible UTC timestamp. Check the poller host clock and monitor.py output.',
        lastStatus
      );
      setLive('stale', 'Invalid status timestamp');
      return;
    }
    const stale = age > STALE_AFTER;
    if (stale) {
      showUnavailable(
        'Status is stale',
        'The last successful status is ' + relativeTime(lastStatus.timestamp) + '. Check monitor.py and refresh AWS credentials.',
        lastStatus
      );
      setLive('stale', 'Stale · updated ' + relativeTime(lastStatus.timestamp));
      return;
    }
    setLive('live', 'Live · updated ' + relativeTime(lastStatus.timestamp));
    renderBanner(lastStatus);
  }
  function startPolling() {
    consumeHashToken();
    if (sessionToken && window.EbaConsole && window.EbaConsole.setSessionToken) {
      window.EbaConsole.setSessionToken(sessionToken);
    }
    const authForm = $('authGateForm');
    if (authForm) {
      authForm.addEventListener('submit', e => {
        e.preventDefault();
        const input = $('authTokenInput');
        const value = (input.value || '').trim();
        input.value = '';
        if (!value) return;
        sessionToken = value;
        if (window.EbaConsole && window.EbaConsole.setSessionToken) {
          window.EbaConsole.setSessionToken(sessionToken);
        }
        fetchStatus();
      });
    }
    if (initialTab && document.getElementById('tab-' + initialTab)) switchTab(initialTab); else fetchStatus();
    setInterval(fetchStatus, POLL_INTERVAL);
    setInterval(tickLive, 1000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) fetchStatus(); });
  }
  startPolling();
})();
