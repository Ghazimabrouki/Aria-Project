# ARIA - Frontend Design Specification

**Service:** ARIA - Adaptive Response Intelligence Automation  
**Version:** 1.4.0

---

## Table of Contents

1. [Design Philosophy](#1-design-philosophy)
2. [Layout Structure](#2-layout-structure)
3. [Navigation](#3-navigation)
4. [Page Designs](#4-page-designs)
5. [Components](#5-components)
6. [State Management](#6-state-management)
7. [Real-time Updates](#7-real-time-updates)
8. [User Flows](#8-user-flows)
9. [Accessibility](#9-accessibility)
10. [Performance](#10-performance)

---

## 1. Design Philosophy

### Core Principles
- **Dark Mode First**: Security operations happen in SOC centers with minimal lighting
- **Density over Simplicity**: Show maximum information without scrolling
- **Color-Coded Severity**: Instant threat recognition
- **Keyboard-First**: Power users prefer keyboard shortcuts
- **Contextual Actions**: Right-click context menus for power users

### Color Palette

```css
/* Primary Colors */
--bg-primary: #0F172A;        /* Main background - Slate 900 */
--bg-secondary: #1E293B;      /* Cards, sidebar - Slate 800 */
--bg-tertiary: #334155;         /* Hover states - Slate 700 */

/* Text Colors */
--text-primary: #F8FAFC;        /* Primary text - Slate 50 */
--text-secondary: #94A3B8;     /* Secondary text - Slate 400 */
--text-muted: #64748B;          /* Muted text - Slate 500 */

/* Severity Colors */
--severity-critical: #EF4444;   /* Red 500 */
--severity-high: #F97316;       /* Orange 500 */
--severity-medium: #EAB308;     /* Yellow 500 */
--severity-low: #3B82F6;        /* Blue 500 */
--severity-info: #6B7280;      /* Gray 500 */

/* Status Colors */
--status-success: #10B981;    /* Emerald 500 */
--status-warning: #F59E0B;   /* Amber 500 */
--status-error: #EF4444;       /* Red 500 */
--status-running: #3B82F6;    /* Blue 500 */
--status-pending: #8B5CF6;    /* Violet 500 */

/* Accent Colors */
--accent-primary: #06B6D4;     /* Cyan 500 - ARIA accent */
--accent-glow: rgba(6, 182, 212, 0.3);
```

### Typography

```css
/* Font Family */
--font-display: 'JetBrains Mono', 'Fira Code', monospace;  /* Headers, data */
--font-body: 'Inter', -apple-system, sans-serif;           /* Body text */

/* Font Sizes */
--text-xs: 0.75rem;    /* 12px - Labels */
--text-sm: 0.875rem;   /* 14px - Secondary */
--text-base: 1rem;    /* 16px - Body */
--text-lg: 1.125rem;  /* 18px - Subheaders */
--text-xl: 1.25rem;   /* 20px - Headers */
--text-2xl: 1.5rem;   /* 24px - Page titles */
--text-3xl: 1.875rem; /* 30px - Dashboard */
```

### Spacing System

```css
--space-1: 0.25rem;   /* 4px */
--space-2: 0.5rem;    /* 8px */
--space-3: 0.75rem;  /* 12px */
--space-4: 1rem;    /* 16px */
--space-6: 1.5rem;   /* 24px */
--space-8: 2rem;    /* 32px */
--space-12: 3rem;   /* 48px */
```

---

## 2. Layout Structure

### Main Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  HEADER BAR (48px)                                                   │
│  [Logo] [Search...        ] [Alerts(5)] [Incidents(2)] [User ▼]     │
├────────────┬────────────────────────────────────────────────────────┤
│            │                                                        │
│  SIDEBAR   │  MAIN CONTENT AREA                                    │
│  (240px)   │                                                        │
│            │  ┌──────────────────────────────────────────────────┐  │
│  📊 Dashboard  │                                                   │  │
│  🔔 Alerts     │  BREADCRUMB: Home / Alerts / Alert Details     │  │
│  📁 Incidents │                                                   │  │
│  🔍 Investig. │  PAGE TITLE                                       │  │
│  🤖 AI Assistant │                                               │  │
│  🗺 IPS Map   │  ┌─────────────────────────────────────────────┐   │  │
│  📈 Perform. │  │                                             │   │  │
│  📦 Archives │  │         CONTENT                             │   │  │
│  ⚙️ Monitor  │  │                                             │   │  │
│            │  │                                             │   │  │
│            │  └─────────────────────────────────────────────┘   │  │
│            │                                                        │
└────────────┴────────────────────────────────────────────────────────┘
```

### Responsive Breakpoints

```css
/* Desktop - Full layout */
@media (min-width: 1280px) {
  .sidebar { width: 240px; }
}

/* Tablet - Collapsible sidebar */
@media (min-width: 768px) and (max-width: 1279px) {
  .sidebar { width: 64px; }  /* Icons only */
  .sidebar:hover { width: 240px; }  /* Expand on hover */
}

/* Mobile - Bottom navigation */
@media (max-width: 767px) {
  .sidebar { display: none; }
  .mobile-nav { display: flex; position: fixed; bottom: 0; width: 100%; }
}
```

---

## 3. Navigation

### Sidebar Navigation

```jsx
// Sidebar items with icons and badges
const navItems = [
  { path: '/', icon: Dashboard, label: 'Dashboard', badge: null },
  { path: '/alerts', icon: Bell, label: 'Alerts', badge: 'alertCount' },
  { path: '/incidents', icon: Folder, label: 'Incidents', badge: 'incidentCount' },
  { path: '/investigations', icon: Search, label: 'Investigations', badge: 'awaitingApprovalCount' },
  { path: '/assistant', icon: Bot, label: 'AI Assistant', badge: null },
  { path: '/ips-map', icon: Globe, label: 'IPS Map', badge: null },
  { path: '/performance', icon: Activity, label: 'Performance', badge: null },
  { path: '/archives', icon: Archive, label: 'Archives', badge: null },
  { path: '/monitor', icon: Settings, label: 'Monitor', badge: null },
];
```

### Quick Actions (Header)

```jsx
// Header quick actions
const quickActions = [
  { icon: Search, action: 'globalSearch', shortcut: 'Cmd+K' },
  { icon: Bell, action: 'alerts', shortcut: 'G then A' },
  { icon: AlertTriangle, action: 'criticalAlerts', shortcut: 'G then C' },
];
```

### Keyboard Shortcuts

```
Global:
- Cmd+K / Ctrl+K: Global search
- G then D: Go to Dashboard
- G then A: Go to Alerts
- G then I: Go to Investigate
- G then M: Go to Monitor
-Esc: Close modal/popover

In Lists:
- ↑/↓: Navigate items
- Enter: Open selected
- S: Sort menu
- F: Filter menu
- E: Export

In Detail View:
- ←/→: Previous/Next
- A: Approve (investigation)
- D: Decline
- R: Refresh
```

---

## 4. Page Designs

### 4.1 Dashboard Page

```jsx
// Dashboard layout
const DashboardPage = () => (
  <div className="dashboard">
    {/* Quick Stats Row */}
    <div className="stats-row">
      <StatCard 
        title="Alerts" 
        value={873} 
        change="+12%" 
        severity="high"
        onClick={() => navigate('/alerts')}
      />
      <StatCard 
        title="Open Incidents" 
        value={216} 
        change="-5%"
        severity="medium"
        onClick={() => navigate('/incidents')}
      />
      <StatCard 
        title="Awaiting Approval" 
        value={52} 
        severity="warning"
        badge="needs-action"
        onClick={() => navigate('/investigations?status=awaiting_approval')}
      />
      <StatCard 
        title="Active Attacks" 
        value={1} 
        severity="critical"
        onClick={() => navigate('/ips-map')}
      />
    </div>

    {/* Main Grid */}
    <div className="dashboard-grid">
      {/* Recent Alerts */}
      <Card title="Recent Alerts" action="/alerts">
        <AlertTable 
          columns={['Time', 'Alert', 'Source', 'Severity']}
          limit={10}
        />
      </Card>

      {/* Investigation Status */}
      <Card title="Investigations" action="/investigations">
        <InvestigationStatusChart />
      </Card>

      {/* Attack Map Preview */}
      <Card title="Live Attacks" action="/ips-map">
        <AttackMapPreview />
      </Card>

      {/* System Health */}
      <Card title="System Health" action="/monitor">
        <ServiceStatusList />
      </Card>
    </div>
  </div>
);
```

### 4.2 Alerts Page

```jsx
const AlertsPage = () => (
  <div className="alerts-page">
    {/* Filters Bar */}
    <div className="filters-bar">
      <SearchInput placeholder="Search alerts..." />
      <FilterDropdown 
        label="Severity" 
        options={['All', 'critical', 'high', 'medium', 'low']} 
      />
      <FilterDropdown 
        label="Source" 
        options={['All', 'wazuh', 'suricata', 'falco', 'filebeat']} 
      />
      <FilterDropdown label="Status" options={['All', 'new', 'open', 'closed']} />
      <DateRangePicker />
      <ExportButton />
    </div>

    {/* Alerts Table */}
    <table className="alerts-table">
      <thead>
        <tr>
          <th className="checkbox"><input type="checkbox" /></th>
          <th>Time</th>
          <th>Alert Name</th>
          <th>Source IP</th>
          <th>Target</th>
          <th>Source</th>
          <th>Severity</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map(alert => (
          <tr key={alert.id} className={`severity-${alert.severity}`}>
            <td><input type="checkbox" /></td>
            <td className="time">{formatTime(alert.created_at)}</td>
            <td className="title">
              <Link to={`/alerts/${alert.id}`}>{alert.title}</Link>
            </td>
            <td className="ip">{alert.source_ip}</td>
            <td className="ip">{alert.dest_ip}</td>
            <td>{alert.source}</td>
            <td>
              <SeverityBadge severity={alert.severity} />
            </td>
            <td><StatusBadge status={alert.status} /></td>
            <td>
              <ActionButton icon="eye" tooltip="View" />
              <ActionButton icon="incidents" tooltip="View Incidents" />
              <ActionButton icon="similar" tooltip="Similar Alerts" />
            </td>
          </tr>
        ))}
      </tbody>
    </table>

    {/* Pagination */}
    <Pagination 
      total={total} 
      page={page} 
      pageSize={pageSize}
      onPageChange={setPage}
    />
  </div>
);
```

### 4.3 Alert Detail Page

```jsx
const AlertDetailPage = ({ alertId }) => (
  <div className="alert-detail">
    {/* Header */}
    <div className="detail-header">
      < breadcrumbs>
        <Link to="/alerts">Alerts</Link> / {alert.title}
      </breadcrumb>
      <h1>{alert.title}</h1>
      <div className="meta">
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
        <span>Created: {formatDate(alert.created_at)}</span>
      </div>
    </div>

    {/* Tabs */}
    <div className="tabs">
      <Tab name="Overview" />
      <Tab name="Raw Data" />
      <Tab name="Incidents" />
      <Tab name="Timeline" />
      <Tab name="Similar" />
    </div>

    {/* Content */}
    <div className="detail-content">
      {/* Overview Tab */}
      <TabPanel name="Overview">
        <div className="overview-grid">
          {/* Description */}
          <Card title="Description">
            <p>{alert.description}</p>
          </Card>

          {/* IOCs */}
          <Card title="Indicators of Compromise">
            <IOCList iocs={alert.iocs} />
          </Card>

          {/* MITRE */}
          <Card title="MITRE ATT&CK">
            <MITRETags tags={alert.tags} />
          </Card>

          {/* Related Entities */}
          <Card title="Related">
            <RelatedList>
              <RelatedItem 
                type="incidents" 
                count={incidents.length} 
                onClick={() => navigate(`/incidents?alert=${alert.id}`)} 
              />
              <RelatedItem 
                type="similar" 
                count={similar.length} 
                onClick={() => navigate(`/alerts/similar/${alert.id}`)} 
              />
            </RelatedList>
          </Card>
        </div>
      </TabPanel>
    </div>
  </div>
);
```

### 4.4 Investigation Approval Page

```jsx
const InvestigationDetailPage = ({ investigationId }) => (
  <div className="investigation-detail">
    {/* Header with Action Buttons */}
    <div className="detail-header">
      <div className="title-section">
        <h1>{investigation.incident_title}</h1>
        <SeverityBadge severity={investigation.severity} />
        <StatusBadge status={investigation.status} />
      </div>
      
      {/* Action Buttons */}
      {investigation.status === 'awaiting_approval' && (
        <div className="action-buttons">
          <Button 
            variant="primary" 
            icon="check"
            onClick={() => approveInvestigation(id)}
          >
            Approve & Execute
          </Button>
          <Button 
            variant="danger" 
            icon="x"
            onClick={() => declineInvestigation(id)}
          >
            Decline
          </Button>
          <Button 
            variant="secondary" 
            icon="edit"
            onClick={() => openPlaybookEditor()}
          >
            Edit Playbook
          </Button>
        </div>
      )}
    </div>

    {/* Tabs */}
    <div className="tabs">
      <Tab name="Overview" active />
      <Tab name="AI Analysis" />
      <Tab name="Playbook" />
      <Tab name="Timeline" />
    </div>

    {/* Tab Content */}
    <TabPanel name="Overview">
      <div className="overview-grid">
        {/* AI Summary */}
        <Card title="AI Summary">
          <div className="ai-content">
            <p>{investigation.ai_summary}</p>
          </div>
        </Card>

        {/* AI Narrative */}
        <Card title="Analysis Narrative" expanded>
          <div className="ai-content narrative">
            <p>{investigation.ai_narrative}</p>
          </div>
        </Card>

        {/* Risk Assessment */}
        <Card title="Risk Assessment">
          <div className="risk-content">
            <RiskBadge risk={investigation.ai_risk} />
            <p>{investigation.ai_risk}</p>
          </div>
        </Card>

        {/* Alerts */}
        <Card title="Linked Alerts">
          <AlertList alerts={investigation.alerts} />
        </Card>
      </div>
    </TabPanel>

    {/* Playbook Tab */}
    <TabPanel name="Playbook">
      <div className="playbook-viewer">
        <div className="playbook-editor">
          {/* YAML Editor */}
          <CodeEditor 
            value={investigation.playbook_yaml}
            language="yaml"
            readOnly={investigation.status !== 'awaiting_approval'}
            onChange={updatePlaybook}
          />
        </div>
      </div>
    </TabPanel>

    {/* Timeline Tab */}
    <TabPanel name="Timeline">
      <Timeline events={investigation.timeline} />
    </TabPanel>
  </div>
);
```

### 4.5 IPS Attack Map Page

```jsx
const IPSMapPage = () => (
  <div className="ips-map-page">
    {/* Map Container */}
    <div className="map-container">
      <WorldMap 
        attacks={attacks}
        paths={attackPaths}
        onAttackClick={selectAttack}
      />
    </div>

    {/* Controls Panel */}
    <div className="map-controls">
      <ButtonGroup>
        <Button variant={viewMode === '2d'} onClick={() => setViewMode('2d')}>2D</Button>
        <Button variant={viewMode === '3d'} onClick={() => setViewMode('3d')}>3D</Button>
      </ButtonGroup>
      
      <Select 
        value={timeRange} 
        onChange={setTimeRange}
        options={['1h', '6h', '24h', '7d']}
      />
    </div>

    {/* Live Events Table */}
    <div className="events-panel">
      <div className="panel-header">
        <h3>Live Events</h3>
        <div className="refresh-controls">
          <Button 
            variant={autoRefresh} 
            icon="pause"
            onClick={toggleAutoRefresh}
          >
            {autoRefresh ? 'Pause' : 'Resume'}
          </Button>
          <Select 
            value={refreshInterval} 
            onChange={setRefreshInterval}
            options={['5s', '10s', '30s']}
          />
        </div>
      </div>

      <table className="events-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Source City</th>
            <th>Dest City</th>
            <th>Severity</th>
            <th>Attack</th>
            <th>Category</th>
            <th>Protocol</th>
          </tr>
        </thead>
        <tbody>
          {events.map(event => (
            <tr key={event.event_id} className={`severity-${event.severity}`}>
              <td>{formatTime(event.timestamp)}</td>
              <td>{event.source_city}, {event.source_country}</td>
              <td>{event.dest_city}, {event.dest_country}</td>
              <td><SeverityBadge severity={event.severity} /></td>
              <td>{event.alert_name}</td>
              <td>{event.category}</td>
              <td>{event.protocol}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>

    {/* Statistics Panel */}
    <div className="stats-panel">
      <StatCard title="Total Attacks" value={stats.total_attacks} />
      <StatCard title="Unique Sources" value={stats.unique_sources} />
      
      <Card title="By Severity">
        <BarChart data={stats.by_severity} />
      </Card>
      
      <Card title="Top Countries">
        <CountryList countries={stats.top_countries} />
      </Card>
    </div>
  </div>
);
```

### 4.6 AI Assistant Page

```jsx
const AssistantPage = () => (
  <div className="assistant-page">
    {/* Data Sources Sidebar */}
    <div className="sources-sidebar">
      <h3>Data Sources</h3>
      <SourceList>
        <SourceItem 
          name="OpenSOAR Alerts" 
          count={sources.alerts}
          icon="bell"
        />
        <SourceItem 
          name="Incidents" 
          count={sources.incidents}
          icon="folder"
        />
        <SourceItem 
          name="Investigations" 
          count={sources.investigations}
          icon="search"
        />
        <SourceItem 
          name="Archives" 
          count={sources.archives}
          icon="archive"
        />
        <SourceItem 
          name="Performance" 
          count={sources.hosts}
          icon="activity"
        />
      </SourceList>

      <h3>Quick Actions</h3>
      <QuickActions>
        <Action onClick={() => ask('Show critical alerts')}>
          🔴 Critical Alerts
        </Action>
        <Action onClick={() => ask('Pending investigations')}>
          ⏳ Pending Investigations
        </Action>
        <Action onClick={() => ask('Top attacking countries')}>
          🌍 Top Attackers
        </Action>
        <Action onClick={() => ask('System health')}>
          💚 System Health
        </Action>
      </QuickActions>
    </div>

    {/* Chat Area */}
    <div className="chat-area">
      <div className="messages">
        {messages.map(message => (
          <Message 
            key={message.id}
            role={message.role}
            content={message.content}
            sources={message.sources}
          />
        ))}
      </div>

      {/* Input */}
      <div className="input-area">
        <textarea 
          value={input}
          onChange={setInput}
          placeholder="Ask anything about your security system..."
          onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
        />
        <Button onClick={sendMessage} variant="primary">
          Send
        </Button>
      </div>
    </div>
  </div>
);
```

---

## 5. Components

### Reusable Components List

| Component | Props | Description |
|-----------|-------|-------------|
| `<StatCard />` | title, value, change, severity, onClick | Dashboard stat |
| `<AlertTable />` | alerts, columns, onRowClick | Alert list |
| `<AlertDetail />` | alert | Alert detail view |
| `<IncidentCard />` | incident | Incident card |
| `<InvestigationCard />` | investigation, actions | Investigation with actions |
| `<SeverityBadge />` | severity | Color-coded severity |
| `<StatusBadge />` | status | Status indicator |
| `<CodeEditor />` | value, language, readOnly, onChange | YAML/JSON editor |
| `<Timeline />` | events | Event timeline |
| `<WorldMap />` | attacks, paths, onClick | Attack map |
| `<LiveTable />` | data, columns, autoRefresh | Real-time table |
| `<FilterDropdown />` | options, value, onChange | Filter dropdown |
| `<Pagination />` | total, page, pageSize, onChange | Pagination |
| `<SearchInput />` | placeholder, onSearch | Search with debounce |
| `<DateRangePicker />` | start, end, onChange | Date range |
| `<Modal />` | isOpen, onClose, title, children | Modal dialog |
| `<Toast />` | message, type, onClose | Notification toast |

### Component States

```jsx
// Button States
<Button variant="primary" size="sm">Small</Button>
<Button variant="secondary" size="md">Medium</Button>
<Button variant="danger" size="lg">Large</Button>
<Button variant="primary" loading>Loading</Button>
<Button variant="primary" disabled>Disabled</Button>

// Input States
<Input state="default" />
<Input state="focus" />
<Input state="error" message="Required" />
<Input state="success" />
<Input state="disabled" />
```

---

## 6. State Management

### Global State Structure

```javascript
// Using React Context + useReducer
const AppState = {
  // User
  user: { id, name, role, preferences },
  
  // Navigation
  currentPage: 'dashboard',
  breadcrumbs: ['Home', 'Dashboard'],
  
  // Filters
  filters: {
    alerts: { severity: null, source: null, status: null },
    incidents: { status: null },
    investigations: { status: null },
  },
  
  // Data Cache
  cache: {
    alerts: { data: [], lastFetch: null },
    incidents: { data: [], lastFetch: null },
    investigations: { data: [], lastFetch: null },
  },
  
  // Real-time
  live: {
    alerts: [],
    attacks: [],
    stats: {},
  },
  
  // UI
  ui: {
    sidebarCollapsed: false,
    theme: 'dark',
    notifications: [],
  },
};
```

### API Call Pattern

```javascript
// Custom hook for API calls
const useAPI = () => {
  const [state, dispatch] = useReducer(appReducer, initialState);
  
  const fetchAlerts = async (params) => {
    dispatch({ type: 'LOADING', resource: 'alerts' });
    try {
      const data = await api.getAlerts(params);
      dispatch({ type: 'SUCCESS', resource: 'alerts', data });
    } catch (error) {
      dispatch({ type: 'ERROR', resource: 'alerts', error });
    }
  };
  
  return { fetchAlerts, ...state };
};
```

---

## 7. Real-time Updates

### WebSocket Connection

```javascript
// WebSocket hook
const useWebSocket = () => {
  const [ws, setWs] = useState(null);
  
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:8001/ws');
    
    ws.onopen = () => console.log('WS Connected');
    
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      
      switch (message.type) {
        case 'new_alert':
          addAlert(message.data);
          showToast('New alert received', 'info');
          break;
        case 'investigation_update':
          updateInvestigation(message.data);
          break;
        case 'attack_event':
          addAttackEvent(message.data);
          break;
        case 'system_alert':
          showSystemAlert(message.data);
          break;
      }
    };
    
    setWs(ws);
    
    return () => ws.close();
  }, []);
};
```

### Polling Fallback

```javascript
// Polling for updates
const usePolling = (endpoints, interval = 30000) => {
  useEffect(() => {
    const poll = async () => {
      for (const endpoint of endpoints) {
        const data = await api.get(endpoint);
        dispatch({ type: 'UPDATE', endpoint, data });
      }
    };
    
    poll();
    const intervalId = setInterval(poll, interval);
    
    return () => clearInterval(intervalId);
  }, [endpoints, interval]);
};
```

---

## 8. User Flows

### Flow 1: Alert Triage

```
1. User sees alert count badge on sidebar
2. Click Alerts → Alert list loads
3. Filter by severity/status
4. Click alert → Alert detail
5. View linked incidents
6. Click incident → Incident detail
7. View timeline
8. Create investigation if needed
```

### Flow 2: Investigation Approval

```
1. Dashboard shows "Awaiting Approval" badge
2. Click → Investigation list filtered by awaiting
3. Click investigation → Detail page
4. Review AI summary, narrative, risk
5. Review playbook YAML
6. Edit if needed
7. Click Approve → Confirmation modal
8. Confirm → Playbook executes
9. Watch execution in run-status
10. View timeline for completion
```

### Flow 3: Live Attack Monitoring

```
1. Navigate to IPS Map
2. See world map with attack arcs
3. Watch live events table
4. Filter by severity/country
5. Click attack → Detail
6. Export for report
```

### Flow 4: Ask AI

```
1. Navigate to AI Assistant
2. Type question in chat
3. View AI response with sources
4. Click source → Navigate to detail
```

---

## 9. Accessibility

### ARIA Labels

```jsx
// All interactive elements must have aria-label
<button aria-label="Approve investigation" />
<input aria-label="Search alerts" />
<select aria-label="Filter by severity" />
```

### Keyboard Navigation

```css
/* Focus styles */
*:focus {
  outline: 2px solid var(--accent-primary);
  outline-offset: 2px;
}

/* Skip to main content */
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  padding: 8px;
  background: var(--accent-primary);
  z-index: 100;
}

.skip-link:focus {
  top: 0;
}
```

### Screen Reader Support

```jsx
// Announce dynamic content changes
const LiveRegion = ({ message }) => (
  <div role="status" aria-live="polite" className="sr-only">
    {message}
  </div>
);
```

---

## 10. Performance

### Optimization Strategies

```javascript
// 1. Virtual scrolling for large lists
const VirtualList = ({ items, rowHeight }) => (
  <div className="virtual-list">
    {items.slice(startIndex, endIndex).map(item => (
      <Row key={item.id} style={{ height: rowHeight }}>
        {item.content}
      </Row>
    ))}
  </div>
);

// 2. React.memo for static components
const StatCard = React.memo(({ title, value }) => (
  <div className="stat-card">{title}: {value}</div>
));

// 3. Code splitting
const InvestigationDetail = React.lazy(() => import('./InvestigationDetail'));

// 4. Image optimization
const OptimizedImage = ({ src, alt }) => (
  <img 
    src={src} 
    alt={alt}
    loading="lazy"
    srcSet={`${src} 1x, ${src.replace('.', '@2x.')} 2x`}
  />
);
```

### Caching Strategy

```javascript
const cacheConfig = {
  '/alerts': { ttl: 30000 },      // 30s
  '/incidents': { ttl: 30000 },   // 30s
  '/investigations': { ttl: 15000 }, // 15s
  '/stats': { ttl: 10000 },       // 10s
  '/ips/map-data': { ttl: 5000 }, // 5s
};
```

---

**Version:** 1.4.0  
**Last Updated:** April 13, 2026