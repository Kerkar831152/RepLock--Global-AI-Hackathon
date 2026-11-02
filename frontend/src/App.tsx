import { createContext, lazy, Suspense, useContext, useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { BrowserRouter, Link, NavLink, Outlet, Route, Routes, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Activity, AlertTriangle, ArrowDownRight, ArrowRight, ArrowUpRight, Bell, BookOpenCheck, Check,
  CheckCircle2, ChevronDown, ChevronRight, Clock3, Code2, Download, ExternalLink, FileCode2,
  FileText, GitBranch, GitPullRequest, GitMerge, Globe2, KeyRound, Layers3, LoaderCircle,
  LockKeyhole, Menu, MoreHorizontal, Play, Plus, Radio, RefreshCw, Search, Server,
  Shield, ShieldAlert, ShieldCheck, ShieldEllipsis, SlidersHorizontal, Sparkles, Terminal,
  TriangleAlert, X,
} from 'lucide-react'
import { repositories, scans, vulnerabilities, reports, pullRequests, scanStages, severityColors, severityDistribution } from './data/mockData'
import { api, getApiErrorMessage } from './services/api'
import { authService } from './services/auth'
import { repositoryService } from './services/repositories'
import { scanService } from './services/scans'
import { vulnerabilityService } from './services/vulnerabilities'
import { mergeIntelligenceService } from './services/mergeIntelligence'
import type { MergeAnalysis } from './services/mergeIntelligence'
import type { Repository, ScanConfiguration, ScanProgressEvent, Vulnerability } from './types'
import './App.css'

const DiffEditor = lazy(() => import('@monaco-editor/react').then((module) => ({ default: module.DiffEditor })))
const VulnerabilityChart = lazy(() => import('./components/VulnerabilityChart'))

type NoticeKind = 'success' | 'error' | 'info'
type Notify = (message: string, kind?: NoticeKind) => void
const NoticeContext = createContext<Notify>(() => undefined)
const navItems = [
  { label: 'Overview', path: '/', icon: Layers3 },
  { label: 'Repositories', path: '/repositories', icon: Code2 },
  { label: 'Security scans', path: '/scans', icon: Radio },
  { label: 'Vulnerabilities', path: '/vulnerabilities', icon: ShieldAlert },
  { label: 'Pull requests', path: '/pull-requests', icon: GitPullRequest },
  { label: 'Merge intelligence', path: '/merge-intelligence', icon: GitMerge },
  { label: 'Reports', path: '/reports', icon: FileText },
]

function useNotify() {
  return useContext(NoticeContext)
}

function NotificationProvider({ children }: { children: ReactNode }) {
  const [notice, setNotice] = useState<{ message: string; kind: NoticeKind } | null>(null)
  const notify: Notify = (message, kind = 'info') => setNotice({ message, kind })
  useEffect(() => {
    if (!notice) return
    const timer = window.setTimeout(() => setNotice(null), 4200)
    return () => window.clearTimeout(timer)
  }, [notice])
  return (
    <NoticeContext.Provider value={notify}>
      {children}
      {notice && (
        <div className={`toast toast-${notice.kind}`} role="status">
          {notice.kind === 'error' ? <TriangleAlert size={17} /> : notice.kind === 'success' ? <CheckCircle2 size={17} /> : <Shield size={17} />}
          <span>{notice.message}</span>
          <button className="icon-button toast-close" aria-label="Dismiss notification" onClick={() => setNotice(null)}><X size={15} /></button>
        </div>
      )}
    </NoticeContext.Provider>
  )
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand-lockup">
      <div className="brand-mark"><Shield size={20} strokeWidth={2.2} /><span /></div>
      {!compact && <div><span className="brand-name">REPLOCK</span><span className="brand-caption">SECURITY PLATFORM</span></div>}
    </div>
  )
}

function GithubMark({ size = 16 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.1c-3.1.68-3.76-1.32-3.76-1.32-.5-1.3-1.24-1.65-1.24-1.65-1.02-.7.08-.69.08-.69 1.12.08 1.71 1.15 1.71 1.15 1 .1.75 2.24 3.78 1.59.1-.73.39-1.22.7-1.5-2.48-.28-5.08-1.24-5.08-5.52 0-1.22.44-2.21 1.15-2.99-.12-.28-.5-1.42.11-2.95 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.11-1.44 3.04-1.14 3.04-1.14.61 1.53.23 2.67.11 2.95.72.78 1.15 1.77 1.15 2.99 0 4.29-2.6 5.23-5.09 5.5.4.35.75 1.02.75 2.06v3.08c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9Z" /></svg>
}

function AppLayout() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const location = useLocation()
  const notify = useNotify()
  const health = useQuery({
    queryKey: ['api-health'],
    queryFn: async () => (await api.get<{ status: string }>('/health')).data,
    retry: false,
    refetchInterval: 60_000,
  })
  const title = navItems.find((item) => item.path === location.pathname)?.label ?? 'Settings'
  return (
    <div className="app-shell">
      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}
      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <Link to="/" className="brand-link" aria-label="RepLock overview"><Brand /></Link>
        <div className="workspace-switcher">
          <div className="workspace-avatar">A</div>
          <div className="workspace-copy"><strong>Acme Security</strong><span>Workspace</span></div>
          <ChevronDown size={15} />
        </div>
        <div className="nav-section-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          {navItems.map(({ label, path, icon: Icon }) => (
            <NavLink key={path} to={path} end={path === '/'} onClick={() => setMobileNavOpen(false)} className={({ isActive }) => `nav-link ${isActive ? 'nav-active' : ''}`}>
              <Icon size={17} strokeWidth={1.8} /><span>{label}</span>
              {label === 'Vulnerabilities' && <span className="nav-count">4</span>}
            </NavLink>
          ))}
        </nav>
        <div className="nav-section-label tools-label">PREFERENCES</div>
        <NavLink to="/settings" onClick={() => setMobileNavOpen(false)} className={({ isActive }) => `nav-link ${isActive ? 'nav-active' : ''}`}>
          <SlidersHorizontal size={17} strokeWidth={1.8} /><span>Settings</span>
        </NavLink>
        <div className="sidebar-bottom">
          <div className="connection-card">
            <div className="connection-heading"><GithubMark size={16} /><span>GitHub connection</span><span className={`connection-dot ${health.isSuccess ? 'online' : ''}`} /></div>
            <p>{health.isSuccess ? 'API connected' : 'Not connected'}</p>
            <Link to="/login" className="connection-link">{health.isSuccess ? 'Manage connection' : 'Connect GitHub'} <ArrowRight size={13} /></Link>
          </div>
          <div className="agent-presence"><span className="presence-pulse" /><div><strong>Security agent</strong><span>Standing by</span></div><MoreHorizontal size={17} /></div>
          <button className="profile-button" onClick={() => notify('Profile settings are not connected to the backend yet.', 'info')}>
            <div className="profile-avatar">VK</div><div className="profile-copy"><strong>Vithal Kerkar</strong><span>Workspace owner</span></div><ChevronDown size={15} />
          </button>
        </div>
      </aside>
      <div className="main-column">
        <header className="topbar">
          <button className="icon-button mobile-menu" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}><Menu size={19} /></button>
          <div className="topbar-breadcrumb"><span>Workspace</span><ChevronRight size={14} /><strong>{title}</strong></div>
          <div className="topbar-actions">
            <span className="preview-chip"><span />PREVIEW DATA</span>
            <button className="icon-button notification-button" aria-label="Notifications" onClick={() => notify('You’re all caught up. No new alerts.', 'info')}><Bell size={17} /><i /></button>
            <span className="topbar-divider" />
            <div className="topbar-user"><div className="profile-avatar">VK</div><ChevronDown size={14} /></div>
          </div>
        </header>
        <main className="page-content"><Outlet /></main>
        <footer className="footer-note"><span>REPLOCK</span><span>Secure every commit. Protect every merge.</span><span>Preview environment</span></footer>
      </div>
    </div>
  )
}

function PageHeading({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: ReactNode }) {
  return <div className="page-heading"><div>{eyebrow && <div className="eyebrow">{eyebrow}</div>}<h1>{title}</h1><p>{description}</p></div>{actions && <div className="heading-actions">{actions}</div>}</div>
}

function Button({ children, variant = 'primary', onClick, type = 'button', disabled = false, className = '' }: { children: ReactNode; variant?: 'primary' | 'secondary' | 'quiet' | 'danger'; onClick?: () => void; type?: 'button' | 'submit'; disabled?: boolean; className?: string }) {
  return <button type={type} onClick={onClick} disabled={disabled} className={`button inline-flex items-center justify-center gap-2 transition-colors disabled:cursor-not-allowed button-${variant} ${className}`}>{children}</button>
}

function StatusBadge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'danger' | 'warning' | 'purple' }) {
  return <span className={`status-badge badge-${tone}`}><span className="status-dot" />{children}</span>
}

function Modal({ title, onClose, children, wide = false }: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])
  return (
    <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}>
      <section className={`modal-card ${wide ? 'modal-wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-header"><h2>{title}</h2><button className="icon-button" aria-label="Close dialog" onClick={onClose}><X size={17} /></button></div>
        <div className="modal-body">{children}</div>
      </section>
    </div>
  )
}

function OverviewPage() {
  const navigate = useNavigate()
  return (
    <>
      <PageHeading eyebrow="MONDAY, NOVEMBER 2, 2026" title="Security overview" description="A clear view of your repository security posture." actions={<Button onClick={() => navigate('/scans')}><Plus size={16} /> New security scan</Button>} />
      <section className="welcome-banner">
        <div className="welcome-icon"><ShieldCheck size={23} /></div>
        <div className="welcome-copy"><div className="welcome-label"><span className="live-dot" /> PLATFORM SNAPSHOT <span className="welcome-separator">·</span> DEMO DATA</div><h2>Your code, under a closer watch.</h2><p>Explore how RepLock maps attack surfaces and validates security findings across your repositories.</p></div>
        <Button variant="secondary" onClick={() => navigate('/scans')}>Explore a scan <ArrowRight size={15} /></Button>
        <div className="banner-grid" aria-hidden="true" />
      </section>
      <section className="metric-grid" aria-label="Security metrics">
        <MetricCard label="Connected repositories" value="4" icon={<Code2 size={17} />} detail="+1 this month" detailTone="positive" />
        <MetricCard label="Total scans" value="28" icon={<Activity size={17} />} detail="Across all repositories" />
        <MetricCard label="Confirmed vulnerabilities" value="11" icon={<ShieldAlert size={17} />} detail="3 resolved this month" detailTone="positive" />
        <MetricCard label="Critical vulnerabilities" value="2" icon={<AlertTriangle size={17} />} detail="Needs your attention" detailTone="negative" alert />
      </section>
      <div className="overview-grid">
        <section className="panel recent-scans-panel">
          <PanelHeading title="Recent security scans" subtitle="Latest activity across your repositories" action={<button className="text-link" onClick={() => navigate('/scans')}>View all <ArrowRight size={14} /></button>} />
          <div className="scan-list">
            {scans.slice(0, 3).map((scan) => (
              <button className="scan-list-row" key={scan.id} onClick={() => navigate(`/scans?repo=${encodeURIComponent(`acme/${scan.repository}`)}`)}>
                <div className={`scan-repo-icon repo-${scan.repository.charAt(0)}`}>{scan.repository.charAt(0).toUpperCase()}</div>
                <div className="scan-list-main"><strong>{scan.repository}</strong><span><GitBranch size={12} /> {scan.branch} <span className="scan-separator">·</span> {scan.commit}</span></div>
                <div className="scan-findings">{scan.findings ? <><b className={scan.critical ? 'critical-text' : ''}>{scan.findings}</b><span> findings</span></> : <span className="clean-label"><Check size={13} /> Clean</span>}</div>
                <div className="scan-date">{scan.startedAt}</div><ChevronRight className="row-chevron" size={15} />
              </button>
            ))}
          </div>
        </section>
        <section className="panel distribution-panel">
          <PanelHeading title="Vulnerability distribution" subtitle="19 findings across all repositories" />
          <div className="chart-wrap">
            <Suspense fallback={<div className="chart-loading"><LoaderCircle size={15} className="spin" />Loading chart…</div>}><VulnerabilityChart /></Suspense>
            <div className="chart-center"><strong>19</strong><span>total findings</span></div>
          </div>
          <div className="chart-legend">{severityDistribution.map((item) => <div key={item.name}><i style={{ background: item.color }} /><span>{item.name}</span><strong>{item.value}</strong></div>)}</div>
        </section>
      </div>
      <div className="overview-grid lower-grid">
        <section className="panel repo-status-panel">
          <PanelHeading title="Repository security" subtitle="Posture at a glance" action={<button className="text-link" onClick={() => navigate('/repositories')}>All repositories <ArrowRight size={14} /></button>} />
          <div className="repo-status-list">{repositories.slice(0, 3).map((repo) => <div className="repo-status-row" key={repo.id}><div className={`repo-mini-icon repo-${repo.name.charAt(0)}`}>{repo.name.charAt(0)}</div><div className="repo-status-name"><strong>{repo.name}</strong><span>{repo.language}</span></div><StatusBadge tone={repo.status === 'Secure' ? 'success' : repo.status === 'At risk' ? 'danger' : 'warning'}>{repo.status}</StatusBadge><span className="repo-status-findings">{repo.findings} findings</span></div>)}</div>
        </section>
        <section className="panel activity-panel">
          <PanelHeading title="Agent activity" subtitle="Recent security operations" />
          <div className="activity-list">
            <ActivityItem icon={<ShieldAlert size={14} />} tone="red" title="Critical finding confirmed" detail="payments-api · SQL injection" time="12 min ago" />
            <ActivityItem icon={<CheckCircle2 size={14} />} tone="green" title="Security assessment complete" detail="customer-portal · 1 finding" time="Yesterday" />
            <ActivityItem icon={<Sparkles size={14} />} tone="purple" title="Attack surface mapped" detail="infrastructure · 14 endpoints" time="Oct 28" />
          </div>
        </section>
      </div>
    </>
  )
}

function MetricCard({ label, value, icon, detail, detailTone, alert = false }: { label: string; value: string; icon: ReactNode; detail: string; detailTone?: 'positive' | 'negative'; alert?: boolean }) {
  return <div className={`metric-card ${alert ? 'metric-alert' : ''}`}><div className="metric-top"><span>{label}</span><span className={`metric-icon ${alert ? 'metric-icon-alert' : ''}`}>{icon}</span></div><div className="metric-value">{value}</div><div className={`metric-detail ${detailTone ?? ''}`}>{detailTone === 'positive' ? <ArrowDownRight size={13} /> : detailTone === 'negative' ? <ArrowUpRight size={13} /> : <span className="metric-detail-dot" />}{detail}</div></div>
}

function PanelHeading({ title, subtitle, action }: { title: string; subtitle: string; action?: ReactNode }) {
  return <div className="panel-heading"><div><h2>{title}</h2><p>{subtitle}</p></div>{action}</div>
}

function ActivityItem({ icon, tone, title, detail, time }: { icon: ReactNode; tone: string; title: string; detail: string; time: string }) {
  return <div className="activity-item"><div className={`activity-icon activity-${tone}`}>{icon}</div><div className="activity-copy"><strong>{title}</strong><span>{detail}</span></div><time>{time}</time></div>
}

function RepositoriesPage() {
  const [selected, setSelected] = useState<Repository | null>(null)
  const [removed, setRemoved] = useState<string[]>([])
  const [needsAttentionOnly, setNeedsAttentionOnly] = useState(false)
  const notify = useNotify()
  const visibleRepos = repositories.filter((repo) => !removed.includes(repo.id) && (!needsAttentionOnly || repo.status !== 'Secure'))
  const disconnect = useMutation({
    mutationFn: repositoryService.disconnect,
    onSuccess: (_, id) => {
      setRemoved((current) => [...current, id])
      notify('Repository disconnected.', 'success')
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })
  return (
    <>
      <PageHeading eyebrow="YOUR CODEBASE" title="Repositories" description="Manage connected repositories and review their security posture." actions={<Link className="button button-primary" to="/login"><Plus size={16} /> Connect repository</Link>} />
      <div className="callout callout-info"><GithubMark size={17} /><span>GitHub connection is prepared for OAuth. Repository data below is preview content until the backend integration is available.</span><Link to="/login">Connect GitHub <ArrowRight size={14} /></Link></div>
      <section className="panel table-panel">
        <div className="table-toolbar"><div><strong>{visibleRepos.length} repositories</strong><span> · Last updated just now</span></div><button className={`filter-button ${needsAttentionOnly ? 'filter-active' : ''}`} aria-pressed={needsAttentionOnly} onClick={() => setNeedsAttentionOnly((current) => !current)}><SlidersHorizontal size={15} />{needsAttentionOnly ? 'Showing at-risk' : 'Needs attention'}</button></div>
        <div className="table-scroll"><table><thead><tr><th>REPOSITORY</th><th>LANGUAGE</th><th>DEFAULT BRANCH</th><th>LAST SCAN</th><th>FINDINGS</th><th>SECURITY STATUS</th><th /></tr></thead><tbody>
          {visibleRepos.map((repo) => <tr key={repo.id}><td><div className="repo-cell"><div className={`repo-mini-icon repo-${repo.name.charAt(0)}`}>{repo.name.charAt(0)}</div><div><strong>{repo.owner}/{repo.name}</strong><span><LockKeyhole size={11} /> Private repository</span></div></div></td><td><span className="language-label"><i className={`language-${repo.language.toLowerCase()}`} />{repo.language}</span></td><td><span className="branch-label"><GitBranch size={13} />{repo.branch}</span></td><td className="muted-cell">{repo.lastScan}</td><td><span className={repo.findings ? 'finding-count' : 'clean-label'}>{repo.findings || <Check size={13} />}{repo.findings ? ' open' : ' Clean'}</span></td><td><StatusBadge tone={repo.status === 'Secure' ? 'success' : repo.status === 'At risk' ? 'danger' : 'warning'}>{repo.status}</StatusBadge></td><td><div className="table-actions"><button title="Start a security scan" className="icon-button action-scan" onClick={() => window.location.assign(`/scans?repo=${encodeURIComponent(repo.id)}`)}><Play size={15} /></button><button title="View repository details" className="icon-button" onClick={() => setSelected(repo)}><ExternalLink size={15} /></button><button title="Disconnect repository" className="icon-button action-disconnect" onClick={() => { if (window.confirm(`Disconnect ${repo.owner}/${repo.name}? This request will be sent to the backend.`)) disconnect.mutate(repo.id) }} disabled={disconnect.isPending}><MoreHorizontal size={16} /></button></div></td></tr>)}
        </tbody></table></div>
        <div className="table-footer"><span>Showing {visibleRepos.length} of {repositories.length - removed.length} repositories</span><span>Preview data <span className="footer-dot" /></span></div>
      </section>
      {selected && <Modal title={`${selected.owner}/${selected.name}`} onClose={() => setSelected(null)}><div className="repo-detail-modal"><div className="detail-repo-hero"><div className={`repo-mini-icon repo-${selected.name.charAt(0)}`}>{selected.name.charAt(0)}</div><div><strong>{selected.name}</strong><span>{selected.owner} · {selected.language}</span></div></div><div className="detail-grid"><Detail label="Default branch" value={selected.branch} /><Detail label="Last scan" value={selected.lastScan} /><Detail label="Open findings" value={String(selected.findings)} /><Detail label="Security status" value={selected.status} /></div><p className="small-muted">Repository details are preview data. Live repository metadata requires a connected GitHub account.</p><Button onClick={() => window.location.assign(`/scans?repo=${encodeURIComponent(selected.id)}`)}><Play size={15} /> Configure scan</Button></div></Modal>}
    </>
  )
}

function Detail({ label, value }: { label: string; value: string }) {
  return <div className="detail-cell"><span>{label}</span><strong>{value}</strong></div>
}

const initialActivity = [
  'Scan configuration is ready. Confirm the authorized scope before submitting.',
  'Scope is restricted to the repository and environment selected above.',
]

function ScanningPage() {
  const [searchParams] = useSearchParams()
  const initialRepo = searchParams.get('repo') || repositories[0].id
  const [repository, setRepository] = useState(initialRepo)
  const [ref, setRef] = useState('main')
  const [environment, setEnvironment] = useState('Staging')
  const [scope, setScope] = useState<string[]>(['HTTP endpoints', 'Authentication & authorization'])
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false)
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [activeEventsUrl, setActiveEventsUrl] = useState<string | undefined>()
  const [progress, setProgress] = useState(0)
  const [activeStage, setActiveStage] = useState(-1)
  const [activity, setActivity] = useState<string[]>(initialActivity)
  const [findingCount, setFindingCount] = useState(0)
  const [streamStatus, setStreamStatus] = useState<'idle' | 'connecting' | 'connected' | 'complete' | 'error'>('idle')
  const notify = useNotify()
  const currentRepo = repositories.find((item) => item.id === repository) ?? repositories[0]
  const startScan = useMutation({
    mutationFn: (configuration: ScanConfiguration) => scanService.start(configuration),
    onSuccess: (response) => {
      setActiveScanId(response.scan_id)
      setActiveEventsUrl(response.events_url)
      setProgress(0)
      setActiveStage(0)
      setFindingCount(0)
      setActivity([`Scan ${response.scan_id} accepted by the backend. Waiting for live agent updates.`])
      setStreamStatus('connecting')
      notify('Scan request accepted. Live progress will appear as the backend reports it.', 'success')
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })
  useEffect(() => {
    if (!activeScanId) return
    const unsubscribe = scanService.subscribe(activeScanId, (event: ScanProgressEvent) => {
      setActivity((current) => [`${event.timestamp ? `${event.timestamp} · ` : ''}${event.message}`, ...current].slice(0, 30))
      if (typeof event.progress === 'number') setProgress(Math.max(0, Math.min(100, event.progress)))
      if (typeof event.stage === 'number') setActiveStage(Math.max(0, Math.min(scanStages.length - 1, event.stage)))
      if (event.type === 'finding') setFindingCount((count) => count + 1)
      if (event.type === 'complete') { setProgress(100); setActiveStage(scanStages.length); setStreamStatus('complete') }
      if (event.type === 'error') setStreamStatus('error')
      else setStreamStatus('connected')
    }, () => {
      setStreamStatus((status) => status === 'complete' ? status : 'error')
      setActivity((current) => ['Live event stream disconnected. The backend scan status has not been verified.', ...current].slice(0, 30))
    }, activeEventsUrl)
    return unsubscribe
  }, [activeEventsUrl, activeScanId])
  const toggleScope = (item: string) => setScope((current) => current.includes(item) ? current.filter((entry) => entry !== item) : [...current, item])
  const submitScan = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    startScan.mutate({ repository, ref, scope, environment, authorizationConfirmed })
  }
  const running = Boolean(activeScanId) && streamStatus !== 'complete' && streamStatus !== 'error'
  return (
    <>
      <PageHeading eyebrow="AUTONOMOUS SECURITY TESTING" title="Security scans" description="Configure an authorized assessment and follow every agent action in real time." actions={<span className="scan-workspace-chip"><span className={`live-dot ${running ? 'live-active' : ''}`} />{running ? 'SCAN IN PROGRESS' : 'SCAN WORKSPACE'}</span>} />
      <div className="scan-layout">
        <section className="panel scan-config-panel">
          <div className="scan-panel-heading"><div className="scan-step-number">01</div><div><h2>Assessment configuration</h2><p>Set a narrow, authorized testing scope.</p></div></div>
          <form onSubmit={submitScan}>
            <label className="field-label" htmlFor="scan-repo">Repository</label>
            <div className="select-wrap"><select id="scan-repo" value={repository} onChange={(event) => { const nextRepo = repositories.find((repo) => repo.id === event.target.value); setRepository(event.target.value); if (nextRepo) setRef(nextRepo.branch) }}>{repositories.map((repo) => <option value={repo.id} key={repo.id}>{repo.owner}/{repo.name}</option>)}</select><ChevronDown size={15} /></div>
            <div className="field-row"><div><label className="field-label" htmlFor="scan-ref">Branch or commit</label><div className="input-with-icon"><GitBranch size={15} /><input id="scan-ref" value={ref} onChange={(event) => setRef(event.target.value)} required placeholder="main or commit SHA" /></div></div><div><label className="field-label" htmlFor="scan-env">Target environment</label><div className="select-wrap"><select id="scan-env" value={environment} onChange={(event) => setEnvironment(event.target.value)}><option>Staging</option><option>Development</option><option>Production (authorized only)</option></select><ChevronDown size={15} /></div></div></div>
            <div className="field-label scope-label">Authorized test scope <span>Choose only what you are permitted to test</span></div>
            <div className="scope-options">
              {['HTTP endpoints', 'Authentication & authorization', 'Dependency analysis', 'Secrets & configuration'].map((item) => <label className="scope-option" key={item}><input type="checkbox" checked={scope.includes(item)} onChange={() => toggleScope(item)} /><span className="custom-checkbox"><Check size={12} /></span><span>{item}</span></label>)}
            </div>
            <div className="authorization-box"><div className="authorization-icon"><LockKeyhole size={16} /></div><label><strong>Authorization confirmation</strong><span>I own this repository or have explicit permission to test this target. Testing will remain within the scope above.</span><span className="authorization-check"><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} /><span>I confirm I am authorized to run these tests.</span></span></label></div>
            <div className="scan-config-summary"><div className="summary-title"><ShieldCheck size={15} /> CONFIGURATION REVIEW</div><div><span>Target</span><strong>{currentRepo.owner}/{currentRepo.name}</strong></div><div><span>Ref & environment</span><strong>{ref || '—'} <i>·</i> {environment}</strong></div><div><span>Authorized scope</span><strong>{scope.length} test areas selected</strong></div></div>
            <Button type="submit" disabled={!authorizationConfirmed || !scope.length || startScan.isPending || running} className="start-scan-button">{startScan.isPending ? <LoaderCircle className="spin" size={17} /> : <Play size={16} fill="currentColor" />}{running ? 'Scan in progress' : startScan.isPending ? 'Submitting scan request…' : 'Start authorized scan'}<ArrowRight size={15} /></Button>
            <p className="scan-disclaimer"><LockKeyhole size={12} /> A scan begins only after the backend accepts your request.</p>
          </form>
        </section>
        <div className="scan-activity-column">
          <section className="panel scan-progress-panel">
            <div className="scan-live-header"><div><div className="eyebrow">LIVE ASSESSMENT</div><h2>{activeScanId ? `Scan ${activeScanId}` : 'Assessment timeline'}</h2></div><StatusBadge tone={streamStatus === 'complete' ? 'success' : streamStatus === 'error' ? 'danger' : running ? 'purple' : 'neutral'}>{streamStatus === 'complete' ? 'Complete' : streamStatus === 'error' ? 'Stream interrupted' : running ? streamStatus === 'connecting' ? 'Connecting' : 'Running' : 'Ready to start'}</StatusBadge></div>
            <div className="progress-overview"><div className="progress-number">{progress}<span>%</span></div><div className="progress-copy"><strong>{activeStage >= 0 && activeStage < scanStages.length ? scanStages[activeStage] : streamStatus === 'complete' ? 'Assessment complete' : 'Waiting for an authorized run'}</strong><span>{activeScanId ? `Run ID ${activeScanId}` : 'No scan is running. Configure the assessment to begin.'}</span></div><div className="progress-track"><span style={{ width: `${progress}%` }} /></div></div>
            <div className="scan-timeline">{scanStages.map((stage, index) => {
              const isDone = streamStatus === 'complete' || index < activeStage
              const isActive = index === activeStage && running
              return <div key={stage} className={`timeline-step ${isDone ? 'timeline-done' : ''} ${isActive ? 'timeline-active' : ''}`}><div className="timeline-marker">{isDone ? <Check size={12} /> : isActive ? <LoaderCircle size={13} className="spin" /> : <span>{String(index + 1).padStart(2, '0')}</span>}</div><div className="timeline-content"><strong>{stage}</strong><span>{stageDescription(index)}</span></div><span className="timeline-state">{isDone ? 'Complete' : isActive ? 'In progress' : 'Queued'}</span></div>
            })}</div>
          </section>
          <div className="scan-insight-grid">
            <div className="panel insight-card"><div className="insight-card-heading"><div className="insight-icon purple"><Layers3 size={15} /></div><span>ATTACK SURFACE</span></div><strong>{running || streamStatus === 'complete' ? 'Mapping repository' : 'Awaiting analysis'}</strong><p>Routes, entry points and trust boundaries are identified during codebase analysis.</p><div className="insight-foot"><span>Architecture mapping</span><StatusBadge tone={activeStage >= 2 ? 'success' : 'neutral'}>{activeStage >= 2 ? 'Active' : 'Queued'}</StatusBadge></div></div>
            <div className="panel insight-card"><div className="insight-card-heading"><div className="insight-icon orange"><Terminal size={15} /></div><span>TEST EXECUTION</span></div><strong>{activeStage >= 5 ? 'Authorized checks running' : 'No tools executing'}</strong><p>Only checks approved by the selected test scope will be considered.</p><div className="insight-foot"><span>Findings detected</span><strong className={findingCount ? 'critical-text' : ''}>{findingCount}</strong></div></div>
          </div>
          <section className="panel agent-log-panel"><div className="log-heading"><div><div className="agent-pulse"><span />AGENT ACTIVITY</div><h2>Execution log</h2></div><span className="log-count">{activity.length} EVENTS</span></div><div className="execution-log">{activity.map((line, index) => <div className="log-line" key={`${line}-${index}`}><span className="log-time">{index === 0 && running ? 'LIVE' : `0${Math.max(1, activity.length - index)}:24`}</span><span className={`log-led ${index === 0 && running ? 'log-led-live' : ''}`} /><span className="log-message">{line}</span></div>)}</div><div className="log-bottom"><span><span className={`live-dot ${streamStatus === 'error' ? 'error-dot' : ''}`} />{running ? 'Streaming events from the scan service' : streamStatus === 'error' ? 'Live updates disconnected; scan status is unverified' : streamStatus === 'complete' ? 'Backend reported the scan complete' : 'Agent log will appear after a scan starts'}</span><span>{findingCount} findings</span></div></section>
        </div>
      </div>
      <section className="panel scan-history-panel"><PanelHeading title="Recent assessments" subtitle="Completed runs from the preview workspace" action={<StatusBadge tone="neutral">Preview data</StatusBadge>} /><div className="scan-history-list">{scans.slice(0, 3).map((scan) => <div className="scan-history-row" key={scan.id}><div className="history-status"><CheckCircle2 size={15} /></div><div className="history-repo"><strong>{scan.repository}</strong><span>{scan.branch} · {scan.commit}</span></div><StatusBadge tone="success">{scan.status}</StatusBadge><span className="history-findings">{scan.findings} findings</span><span className="history-date"><Clock3 size={13} />{scan.startedAt}</span><button className="icon-button" aria-label={`View ${scan.id}`} onClick={() => notify('Historical scan details are available in the generated report preview.', 'info')}><ChevronRight size={16} /></button></div>)}</div></section>
    </>
  )
}

function stageDescription(index: number) {
  return [
    'Create an isolated workspace for the selected revision.',
    'Index source files, dependencies and security-relevant patterns.',
    'Identify services, data flows and trust boundaries.',
    'Map externally reachable routes and sensitive entry points.',
    'Build a scoped plan based on the authorized test areas.',
    'Run approved checks against the selected environment.',
    'Reproduce candidates and separate confirmed from suspected issues.',
    'Assemble evidence, validation results and remediation guidance.',
  ][index]
}

const severityFilters = ['All severities', 'Critical', 'High', 'Medium', 'Low'] as const
const validationFilters = ['All validation', 'Confirmed', 'Suspected'] as const
const remediationFilters = ['All remediation', 'Open', 'In progress', 'Resolved'] as const

function VulnerabilitiesPage() {
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState<string>('All severities')
  const [validation, setValidation] = useState<string>('All validation')
  const [remediation, setRemediation] = useState<string>('All remediation')
  const [selected, setSelected] = useState<Vulnerability | null>(null)
  const [retested, setRetested] = useState<string[]>([])
  const notify = useNotify()
  const filtered = vulnerabilities.filter((item) => {
    const matchesText = `${item.title} ${item.repository} ${item.file} ${item.id}`.toLowerCase().includes(query.toLowerCase())
    return matchesText && (severity === 'All severities' || item.severity === severity) && (validation === 'All validation' || item.validation === validation) && (remediation === 'All remediation' || item.remediation === remediation)
  })
  const retest = useMutation({
    mutationFn: vulnerabilityService.retest,
    onSuccess: (_, id) => { setRetested((current) => [...current, id]); notify('Retest request accepted by the backend.', 'success') },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })
  return (
    <>
      <PageHeading eyebrow="FINDINGS & REMEDIATION" title="Vulnerabilities" description="Prioritize validated findings and track remediation across your repositories." actions={<Button variant="secondary" onClick={downloadFindings}><Download size={15} /> Export findings CSV</Button>} />
      <div className="finding-summary-row"><div><span className="summary-severity-dot" style={{ background: severityColors.Critical }} /><strong>2</strong><span>Critical</span></div><div><span className="summary-severity-dot" style={{ background: severityColors.High }} /><strong>5</strong><span>High</span></div><div><span className="summary-severity-dot" style={{ background: severityColors.Medium }} /><strong>8</strong><span>Medium</span></div><div><span className="summary-severity-dot" style={{ background: severityColors.Low }} /><strong>4</strong><span>Low</span></div><div className="summary-spacer" /><StatusBadge tone="neutral">Preview findings</StatusBadge></div>
      <section className="panel table-panel findings-panel">
        <div className="table-toolbar findings-toolbar"><div><strong>{filtered.length} findings</strong><span> · Confirmed and suspected issues</span></div><div className="table-filters"><label className="search-field"><Search size={15} /><input aria-label="Search vulnerabilities" placeholder="Search findings..." value={query} onChange={(event) => setQuery(event.target.value)} /></label><div className="select-wrap select-small"><select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>{severityFilters.map((item) => <option key={item}>{item}</option>)}</select><ChevronDown size={14} /></div><div className="select-wrap select-small"><select aria-label="Filter by validation status" value={validation} onChange={(event) => setValidation(event.target.value)}>{validationFilters.map((item) => <option key={item}>{item}</option>)}</select><ChevronDown size={14} /></div><div className="select-wrap select-small"><select aria-label="Filter by remediation status" value={remediation} onChange={(event) => setRemediation(event.target.value)}>{remediationFilters.map((item) => <option key={item}>{item}</option>)}</select><ChevronDown size={14} /></div></div></div>
        <div className="table-scroll"><table className="findings-table"><thead><tr><th>FINDING</th><th>SEVERITY</th><th>REPOSITORY</th><th>AFFECTED FILE</th><th>DETECTION SOURCE</th><th>VALIDATION</th><th>REMEDIATION</th><th /></tr></thead><tbody>{filtered.map((item) => <tr key={item.id} onClick={() => setSelected(item)} className="clickable-row"><td><div className="finding-title-cell"><span className="finding-id">{item.id}</span><strong>{item.title}</strong></div></td><td><SeverityPill severity={item.severity} /></td><td className="muted-cell">{item.repository}</td><td><span className="file-location"><FileCode2 size={13} />{item.file}<em>:{item.line}</em></span></td><td className="muted-cell">{item.source}</td><td><StatusBadge tone={item.validation === 'Confirmed' ? 'danger' : 'warning'}>{item.validation}</StatusBadge></td><td><StatusBadge tone={item.remediation === 'Resolved' ? 'success' : item.remediation === 'In progress' ? 'purple' : 'neutral'}>{item.remediation}</StatusBadge></td><td><ChevronRight size={15} className="row-chevron" /></td></tr>)}</tbody></table></div>
        {filtered.length === 0 && <div className="empty-state"><Search size={20} /><strong>No matching findings</strong><span>Try a different search or filter.</span></div>}
        <div className="table-footer"><span>Showing {filtered.length} preview findings</span><span>Updated just now <span className="footer-dot" /></span></div>
      </section>
      {selected && <Modal title="Finding details" onClose={() => setSelected(null)} wide><FindingDetails finding={selected} onRetest={() => retest.mutate(selected.id)} pending={retest.isPending} wasRetested={retested.includes(selected.id)} /></Modal>}
    </>
  )
}

function SeverityPill({ severity }: { severity: Vulnerability['severity'] }) {
  return <span className={`severity-pill severity-${severity.toLowerCase()}`}><span />{severity}</span>
}

function downloadFindings() {
  const headers = ['ID', 'Title', 'Severity', 'Repository', 'File', 'Line', 'Detection source', 'Validation', 'Remediation']
  const rows = vulnerabilities.map((finding) => [finding.id, finding.title, finding.severity, finding.repository, finding.file, String(finding.line), finding.source, finding.validation, finding.remediation])
  const csv = [headers, ...rows].map((row) => row.map((field) => `"${field.replaceAll('"', '""')}"`).join(',')).join('\r\n')
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'replock-preview-findings.csv'
  link.click()
  URL.revokeObjectURL(url)
}

function FindingDetails({ finding, onRetest, pending, wasRetested }: { finding: Vulnerability; onRetest: () => void; pending: boolean; wasRetested: boolean }) {
  return <div className="finding-detail-content"><div className="finding-detail-title"><SeverityPill severity={finding.severity} /><StatusBadge tone={finding.validation === 'Confirmed' ? 'danger' : 'warning'}>{finding.validation} vulnerability</StatusBadge><span className="finding-id">{finding.id}</span></div><h3>{finding.title}</h3><div className="finding-detail-meta"><span><Code2 size={13} />{finding.repository}</span><span><FileCode2 size={13} />{finding.file}:{finding.line}</span><span><Activity size={13} />{finding.source}</span></div>{finding.validation === 'Suspected' && <div className="callout callout-warning"><AlertTriangle size={16} /><span>This finding is suspected, not confirmed. Runtime validation is required before treating it as exploitable.</span></div>}<div className="finding-detail-sections"><DetailSection title="Description" text={finding.description} /><DetailSection title="Potential impact" text={finding.impact} /><DetailSection title="AI-generated explanation" text={finding.explanation} /><DetailSection title="Evidence" text={finding.evidence} /><DetailSection title="Reproduction information" text={finding.reproduction} /><DetailSection title="Suggested remediation" text={finding.fix} /></div><div className="code-snippet"><div><span><Code2 size={13} /> AFFECTED CODE</span><span>{finding.file}:{finding.line}</span></div><pre><code>{finding.snippet}</code></pre></div><div className="finding-detail-footer"><StatusBadge tone={finding.remediation === 'Resolved' ? 'success' : finding.remediation === 'In progress' ? 'purple' : 'neutral'}>{finding.remediation} remediation</StatusBadge><Button onClick={onRetest} disabled={pending || wasRetested}>{pending ? <LoaderCircle size={15} className="spin" /> : wasRetested ? <Check size={15} /> : <RefreshCw size={15} />}{wasRetested ? 'Retest requested' : 'Request retest'}</Button></div></div>
}

function DetailSection({ title, text }: { title: string; text: string }) {
  return <div className="detail-section"><h4>{title}</h4><p>{text}</p></div>
}

function ReportsPage() {
  const [selected, setSelected] = useState<(typeof reports)[number] | null>(null)
  return (
    <>
      <PageHeading eyebrow="ASSESSMENT HISTORY" title="Security reports" description="Evidence-backed assessment summaries for your repositories." actions={<Button variant="secondary" onClick={() => setSelected(reports[0])}><FileText size={15} /> Preview latest report</Button>} />
      <div className="callout callout-info"><FileText size={17} /><span>Reports contain validation status, evidence and remediation guidance. Preview reports below are sample content.</span><span className="callout-tail">PDF export via browser print</span></div>
      <section className="panel table-panel">
        <div className="table-toolbar"><div><strong>{reports.length} reports</strong><span> · Completed assessments</span></div><div className="table-filters"><span className="mini-filter"><CheckCircle2 size={13} /> Complete</span></div></div>
        <div className="table-scroll"><table><thead><tr><th>REPORT</th><th>REPOSITORY</th><th>COMMIT</th><th>GENERATED</th><th>FINDINGS</th><th>CRITICAL</th><th>STATUS</th><th /></tr></thead><tbody>{reports.map((report) => <tr key={report.id}><td><div className="report-id-cell"><div className="report-icon"><FileText size={16} /></div><strong>{report.id}</strong></div></td><td className="strong-cell">{report.repository}</td><td><code className="commit-code">{report.commit}</code></td><td className="muted-cell">{report.date}</td><td>{report.findings}</td><td>{report.critical ? <span className="critical-text">{report.critical}</span> : <span className="muted-cell">0</span>}</td><td><StatusBadge tone="success">{report.status}</StatusBadge></td><td><Button variant="quiet" onClick={() => setSelected(report)}>Preview <ArrowRight size={14} /></Button></td></tr>)}</tbody></table></div>
        <div className="table-footer"><span>Preview reports are not generated by a live assessment.</span><span>3 of 3</span></div>
      </section>
      {selected && <Modal title={`Assessment report · ${selected.id}`} onClose={() => setSelected(null)} wide><div className="report-preview" id="print-report"><div className="report-cover"><div className="report-brand"><Brand compact /><span>SECURITY ASSESSMENT</span></div><div className="report-cover-body"><div className="eyebrow">REPOSITORY SECURITY ASSESSMENT</div><h2>{selected.repository}</h2><p>Evidence-backed security assessment report</p><div className="report-cover-meta"><Detail label="Commit" value={selected.commit} /><Detail label="Assessment date" value={selected.date} /><Detail label="Report ID" value={selected.id} /></div></div></div><div className="report-summary-grid"><div><span>Total findings</span><strong>{selected.findings}</strong></div><div><span>Critical</span><strong className={selected.critical ? 'critical-text' : ''}>{selected.critical}</strong></div><div><span>Validation</span><strong>Evidence reviewed</strong></div></div><h3>Executive summary</h3><p className="report-body-copy">This preview summarizes a completed sample security assessment of <strong>{selected.repository}</strong> at commit <code>{selected.commit}</code>. Findings are presented with explicit validation status, evidence and remediation guidance.</p><h3>Findings & evidence</h3>{vulnerabilities.filter((finding) => finding.repository === selected.repository).map((finding) => <div className="report-finding" key={finding.id}><div><SeverityPill severity={finding.severity} /><StatusBadge tone={finding.validation === 'Confirmed' ? 'danger' : 'warning'}>{finding.validation}</StatusBadge></div><strong>{finding.title}</strong><span>{finding.file}:{finding.line} · {finding.source}</span><p>{finding.evidence}</p><p><strong>Recommendation:</strong> {finding.fix}</p></div>)}{vulnerabilities.every((finding) => finding.repository !== selected.repository) && <div className="empty-report"><CheckCircle2 size={17} /> No findings in this preview assessment.</div>}<div className="report-print-action"><span>Use your browser’s print dialog to save this report as a PDF.</span><Button onClick={() => window.print()}><Download size={15} /> Print / Save as PDF</Button></div></div></Modal>}
    </>
  )
}

function PullRequestsPage() {
  const [selected, setSelected] = useState<(typeof pullRequests)[number] | null>(null)
  const [query, setQuery] = useState('')
  const visible = pullRequests.filter((pr) => `${pr.title} ${pr.repository} ${pr.author} ${pr.number}`.toLowerCase().includes(query.toLowerCase()))
  return (
    <>
      <PageHeading eyebrow="CHANGE REVIEW" title="Pull request security" description="Catch security regressions and risky changes before they merge." actions={<Link className="button button-secondary" to="/login"><GithubMark size={15} /> Connect GitHub</Link>} />
      <div className="callout callout-info"><GitPullRequest size={17} /><span>PR reviews are examples. Connect GitHub and configure the backend to analyze live pull requests.</span><Link to="/login">Set up connection <ArrowRight size={14} /></Link></div>
      <section className="panel table-panel">
        <div className="table-toolbar"><div><strong>Open pull requests</strong><span> · Security review status</span></div><label className="search-field"><Search size={15} /><input aria-label="Search pull requests" placeholder="Search pull requests..." value={query} onChange={(event) => setQuery(event.target.value)} /></label></div>
        <div className="table-scroll"><table><thead><tr><th>PULL REQUEST</th><th>REPOSITORY</th><th>AUTHOR</th><th>BRANCHES</th><th>CHANGED FILES</th><th>FINDINGS</th><th>REVIEW STATUS</th><th /></tr></thead><tbody>{visible.map((pr) => <tr key={pr.id} className="clickable-row" onClick={() => setSelected(pr)}><td><div className="pr-title-cell"><GitPullRequest size={15} /><div><strong>{pr.title}</strong><span>#{pr.number}</span></div></div></td><td className="muted-cell">{pr.repository}</td><td className="muted-cell">{pr.author}</td><td><span className="pr-branches">{pr.source} <ArrowRight size={12} /> {pr.target}</span></td><td>{pr.files} files</td><td>{pr.findings ? <span className="critical-text">{pr.findings} {pr.findings === 1 ? 'finding' : 'findings'}</span> : <span className="clean-label"><Check size={13} /> None</span>}</td><td><StatusBadge tone={pr.status === 'Passed' ? 'success' : 'warning'}>{pr.status}</StatusBadge></td><td><ChevronRight size={15} className="row-chevron" /></td></tr>)}</tbody></table></div>
        {visible.length === 0 && <div className="empty-state"><Search size={20} /><strong>No matching pull requests</strong></div>}
        <div className="table-footer"><span>{visible.length} preview pull requests</span><span>Last synced — <span className="footer-dot" /></span></div>
      </section>
      {selected && <Modal title={`PR #${selected.number} · ${selected.repository}`} onClose={() => setSelected(null)} wide><PullRequestDetails request={selected} /></Modal>}
    </>
  )
}

function PullRequestDetails({ request }: { request: (typeof pullRequests)[number] }) {
  const navigate = useNavigate()
  return <div className="pr-detail"><div className="pr-detail-header"><div className="pr-detail-icon"><GitPullRequest size={19} /></div><div><h3>{request.title}</h3><p>#{request.number} opened by <strong>{request.author}</strong> · {request.source} → {request.target}</p></div><StatusBadge tone={request.status === 'Passed' ? 'success' : 'warning'}>{request.status}</StatusBadge></div><div className="pr-detail-grid"><div className="pr-code-panel"><div className="code-panel-heading"><FileCode2 size={14} /> src/routes/search.ts <span>+12 −4</span></div><div className="diff-preview"><div className="diff-line diff-context"><span>82</span><code>const search = req.query.search</code></div><div className="diff-line diff-remove"><span>83</span><code>- const query = buildSearch(search)</code></div><div className="diff-line diff-add"><span>84</span><code>+ {request.diff}</code></div><div className="diff-line diff-context"><span>85</span><code>return db.execute(query)</code></div></div></div><div className="pr-review-findings"><div className="eyebrow">SECURITY REVIEW</div><h4>{request.findings ? `${request.findings} security finding${request.findings > 1 ? 's' : ''}` : 'No findings detected'}</h4>{request.findings ? <div className="pr-finding-card"><SeverityPill severity="Critical" /><strong>Potential SQL injection</strong><p>Untrusted search input appears in a dynamically constructed SQL statement.</p><span>src/routes/search.ts:84 · Verify parameterization before merge.</span></div> : <p className="small-muted">No security issues were identified in this sample review.</p>}<h4 className="review-subheading">Additional checks</h4><div className="review-check"><CheckCircle2 size={14} /> Dependency risk <span>None detected</span></div><div className="review-check warning"><AlertTriangle size={14} /> Breaking changes <span>Review required</span></div></div></div><div className="ai-review-note"><Sparkles size={16} /><div><strong>AI review explanation</strong><p>Review this change in the context of its callers and data flow. The security explanation and findings shown here are sample content, not a live analysis.</p></div></div><div className="pr-detail-actions"><span>Review actions require a connected GitHub integration.</span><Button variant="secondary" onClick={() => navigate('/login')}><GithubMark size={15} /> Connect GitHub</Button></div></div>
}

function MergeIntelligencePage() {
  const [repository, setRepository] = useState(repositories[0].id)
  const [branchA, setBranchA] = useState('feat/invoice-search')
  const [branchB, setBranchB] = useState('fix/export-authz')
  const [analysisError, setAnalysisError] = useState('')
  const [backendAnalysis, setBackendAnalysis] = useState<MergeAnalysis | null>(null)
  const notify = useNotify()
  const analyze = useMutation({
    mutationFn: () => mergeIntelligenceService.analyze(repository, branchA, branchB),
    onSuccess: (analysis) => { setBackendAnalysis(analysis); setAnalysisError(''); notify('Merge analysis completed by the backend.', 'success') },
    onError: (error) => { setAnalysisError(getApiErrorMessage(error)); notify(getApiErrorMessage(error), 'error') },
  })
  const original = [
    'export async function getInvoice(user, accountId) {',
    '  const invoices = await db.invoice.findMany({',
    '    where: { accountId }',
    '  })',
    '  return invoices',
    '}',
  ].join('\n')
  const modified = [
    'export async function searchInvoices(user, search) {',
    '  const query = `SELECT * FROM invoices',
    "    WHERE name LIKE '%${search}%'`",
    '  return db.execute(query)',
    '}',
  ].join('\n')
  const analysisTone = backendAnalysis && backendAnalysis.conflicts === 0 ? 'success' : 'warning'
  const analysisStatus = backendAnalysis && backendAnalysis.conflicts === 0 ? 'No conflicts reported' : 'Review suggested'
  return (
    <>
      <PageHeading eyebrow="LOGICAL CONFLICT DETECTION" title="Merge intelligence" description="Find behavior-level conflicts that ordinary line-based diffs can miss." actions={<StatusBadge tone="purple"><Sparkles size={13} /> Semantic analysis</StatusBadge>} />
      <div className="callout callout-info"><GitMerge size={17} /><span>This preview demonstrates how RepLock can surface related changes across branches—not just overlapping lines.</span><span className="callout-tail">Sample analysis</span></div>
      <section className="panel merge-config"><div className="merge-select"><label className="field-label" htmlFor="merge-repo">Repository</label><div className="select-wrap"><select id="merge-repo" value={repository} onChange={(event) => setRepository(event.target.value)}>{repositories.map((repo) => <option key={repo.id} value={repo.id}>{repo.owner}/{repo.name}</option>)}</select><ChevronDown size={14} /></div></div><div className="merge-select"><label className="field-label" htmlFor="branch-a">Branch A</label><div className="input-with-icon"><GitBranch size={14} /><input id="branch-a" value={branchA} onChange={(event) => setBranchA(event.target.value)} /></div></div><div className="merge-connector"><GitMerge size={16} /></div><div className="merge-select"><label className="field-label" htmlFor="branch-b">Branch B</label><div className="input-with-icon"><GitBranch size={14} /><input id="branch-b" value={branchB} onChange={(event) => setBranchB(event.target.value)} /></div></div><Button onClick={() => analyze.mutate()} disabled={analyze.isPending}>{analyze.isPending ? <LoaderCircle size={15} className="spin" /> : <Sparkles size={15} />}Analyze changes</Button></section>
      {analysisError && <div className="inline-error"><TriangleAlert size={15} />{analysisError}</div>}
      <div className="merge-summary-banner"><div className="merge-summary-icon">{analysisTone === 'success' ? <CheckCircle2 size={18} /> : <TriangleAlert size={18} />}</div><div><span className="eyebrow">{backendAnalysis ? 'BACKEND ANALYSIS' : 'SAMPLE LOGICAL CONFLICT'}</span><h2>{backendAnalysis ? `${backendAnalysis.conflicts} potential logical conflict${backendAnalysis.conflicts === 1 ? '' : 's'} reported` : 'Invoice search bypasses account-level authorization'}</h2><p>{backendAnalysis ? backendAnalysis.explanation : 'Changes in both branches touch invoice data access but modify different functions.'}</p></div><StatusBadge tone={analysisTone}>{analysisStatus}</StatusBadge></div>
      <section className="panel merge-editor-panel"><div className="merge-editor-heading"><div><h2>Related code paths</h2><p>Illustrative function-level comparison across two branches</p></div><div className="editor-legend"><span><i className="legend-a" />Branch A</span><span><i className="legend-b" />Branch B</span><span className="editor-language">TYPESCRIPT</span></div></div><div className="editor-container"><Suspense fallback={<div className="editor-loading"><LoaderCircle size={16} className="spin" />Loading diff editor…</div>}><DiffEditor height="340px" language="typescript" original={original} modified={modified} originalModelPath="inmemory://replock/branch-a.ts" modifiedModelPath="inmemory://replock/branch-b.ts" theme="vs-dark" keepCurrentOriginalModel keepCurrentModifiedModel options={{ readOnly: true, minimap: { enabled: false }, renderSideBySide: true, scrollBeyondLastLine: false, fontSize: 12, lineNumbers: 'on', automaticLayout: true, wordWrap: 'on', originalEditable: false, overviewRulerBorder: false }} /></Suspense></div><div className="editor-footer"><span><FileCode2 size={13} /> src/services/invoices.ts</span><span><span className="editor-footer-dot" />Read-only comparison</span></div></section>
      <div className="merge-detail-grid"><section className="panel related-functions"><PanelHeading title="Related functions & dependencies" subtitle="Shared data flows identified between branches" /><div className="function-flow"><div className="function-node"><span className="function-node-icon branch-a-icon"><Code2 size={14} /></span><div><strong>searchInvoices()</strong><span>feat/invoice-search · Added</span></div></div><div className="flow-line"><span>reads invoice records</span></div><div className="function-node"><span className="function-node-icon shared-icon"><Layers3 size={14} /></span><div><strong>invoice data store</strong><span>Shared dependency</span></div></div><div className="flow-line"><span>expects account scope</span></div><div className="function-node"><span className="function-node-icon branch-b-icon"><KeyRound size={14} /></span><div><strong>getInvoice()</strong><span>fix/export-authz · Updated</span></div></div></div></section><section className="panel impact-panel"><PanelHeading title="Conflict analysis" subtitle="Why this may matter" /><div className="impact-callout"><AlertTriangle size={16} /><div><strong>Authorization behavior may diverge</strong><p>Branch B adds account membership checks to <code>getInvoice()</code>, but Branch A introduces a separate search query that reads invoice records directly. If merged without equivalent authorization, the new search path may bypass the intended account boundary.</p></div></div><div className="impact-foot"><div><span>Potential impact</span><strong>Cross-account data exposure</strong></div><div><span>Suggested resolution</span><strong>Apply shared account authorization to search</strong></div></div></section></div>
    </>
  )
}

function SettingsPage() {
  const health = useQuery({ queryKey: ['settings-api-health'], queryFn: async () => (await api.get<{ status: string }>('/health')).data, retry: false })
  return <><PageHeading eyebrow="WORKSPACE PREFERENCES" title="Settings" description="Integration status and workspace configuration." /><section className="panel settings-panel"><PanelHeading title="Backend connection" subtitle="RepLock API endpoint and service availability" /><div className="settings-row"><div className="settings-icon"><Server size={17} /></div><div><strong>API base URL</strong><span>Configured using the VITE_API_URL environment variable.</span></div><code>{import.meta.env.VITE_API_URL || 'http://localhost:8000'}</code></div><div className="settings-row"><div className="settings-icon"><Activity size={17} /></div><div><strong>Backend health</strong><span>{health.isSuccess ? 'Health endpoint responded successfully.' : health.isLoading ? 'Checking backend availability…' : 'Unable to reach the health endpoint.'}</span></div><StatusBadge tone={health.isSuccess ? 'success' : health.isLoading ? 'neutral' : 'danger'}>{health.isSuccess ? 'Connected' : health.isLoading ? 'Checking' : 'Offline'}</StatusBadge></div><div className="settings-row"><div className="settings-icon"><GithubMark size={17} /></div><div><strong>GitHub OAuth</strong><span>Authentication is not configured in the current backend.</span></div><Link className="text-link" to="/login">View setup <ArrowRight size={14} /></Link></div></section><div className="settings-note"><ShieldEllipsis size={16} /><span>Workspace and user management are intentionally minimal in this preview.</span></div></>
}

function LoginPage() {
  const [errorMessage, setErrorMessage] = useState('')
  const beginOAuth = useMutation({
    mutationFn: authService.beginGithubOAuth,
    onError: (error) => setErrorMessage(getApiErrorMessage(error)),
  })
  return <div className="login-page"><header className="login-topbar"><Link to="/" className="brand-link"><Brand /></Link><Link to="/" className="login-back"><ArrowRight size={14} /> Back to workspace</Link></header><main className="login-content"><div className="login-card"><div className="login-logo"><Brand compact /></div><div className="eyebrow">SECURE EVERY COMMIT. PROTECT EVERY MERGE.</div><h1>Security that ships<br />with your code.</h1><p className="login-description">RepLock maps your repository’s attack surface, runs authorized security tests, validates findings and gives your team clear, evidence-backed fixes.</p><div className="login-benefits"><div><span><ShieldCheck size={15} /></span><p><strong>Autonomous security testing</strong><small>Scoped assessments with a live activity trail.</small></p></div><div><span><BookOpenCheck size={15} /></span><p><strong>Evidence-backed findings</strong><small>Understand impact, validation and remediation.</small></p></div><div><span><GitMerge size={15} /></span><p><strong>Safer merges</strong><small>Catch security and semantic conflicts early.</small></p></div></div><Button className="github-login-button" onClick={() => { setErrorMessage(''); beginOAuth.mutate() }} disabled={beginOAuth.isPending}>{beginOAuth.isPending ? <LoaderCircle className="spin" size={17} /> : <GithubMark size={17} />}{beginOAuth.isPending ? 'Connecting to GitHub…' : 'Continue with GitHub'}<ArrowRight size={15} /></Button>{errorMessage && <div className="login-error" role="alert"><TriangleAlert size={15} /><span>{errorMessage} GitHub sign-in is not simulated; configure the backend OAuth endpoint to continue.</span></div>}<div className="login-privacy"><LockKeyhole size={13} /> Read-only until you explicitly authorize a security assessment.</div></div><div className="login-side-art"><div className="login-art-orbit orbit-one" /><div className="login-art-orbit orbit-two" /><div className="login-art-core"><Shield size={43} /><span /></div><div className="art-data art-data-one"><span className="art-data-dot" /> ATTACK SURFACE MAPPED <Check size={13} /></div><div className="art-data art-data-two"><span className="art-data-dot red" /> VULNERABILITY VALIDATED <AlertTriangle size={13} /></div><div className="art-data art-data-three"><span className="art-data-dot green" /> EVIDENCE COLLECTED <Check size={13} /></div><div className="login-art-caption"><span>SECURITY, WITH CONTEXT</span><p>Every finding, grounded in your code.</p></div></div></main><footer className="login-footer"><span>REPLOCK © 2026</span><span>Secure every commit. Protect every merge.</span><span><Globe2 size={13} /> Built for engineering teams</span></footer></div>
}

function NotFoundPage() {
  return <div className="not-found"><Shield size={25} /><h1>Page not found</h1><p>The page you’re looking for doesn’t exist.</p><Link className="button button-primary" to="/">Return to overview</Link></div>
}

function App() {
  return <NotificationProvider><BrowserRouter><Routes><Route path="/login" element={<LoginPage />} /><Route element={<AppLayout />}><Route index element={<OverviewPage />} /><Route path="repositories" element={<RepositoriesPage />} /><Route path="scans" element={<ScanningPage />} /><Route path="vulnerabilities" element={<VulnerabilitiesPage />} /><Route path="pull-requests" element={<PullRequestsPage />} /><Route path="merge-intelligence" element={<MergeIntelligencePage />} /><Route path="reports" element={<ReportsPage />} /><Route path="settings" element={<SettingsPage />} /><Route path="*" element={<NotFoundPage />} /></Route></Routes></BrowserRouter></NotificationProvider>
}

export default App
