import {
  useCallback,
  createContext,
  lazy,
  Suspense,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { createPortal } from 'react-dom'
import {
  BrowserRouter,
  Link,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Bell,
  BookOpenCheck,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  FileCode2,
  FileText,
  GitBranch,
  GitMerge,
  GitPullRequest,
  Globe2,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  MoreHorizontal,
  Plus,
  Play,
  Radio,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  Sparkles,
  TriangleAlert,
  X,
} from 'lucide-react'
import { healthApi, getApiErrorMessage } from './services/api'
import { authService } from './services/auth'
import { repositoryService } from './services/repositories'
import { isScanRequestTimeout, scanService } from './services/scans'
import type { ScanFinding, ScanRecord, ScanRunResult } from './services/scans'
import { dashboardService } from './services/dashboard'
import { pullRequestService } from './services/pullRequests'
import type {
  PullRequest,
  PullRequestReview,
} from './services/pullRequests'
import { downloadReport, reportService } from './services/reports'
import type { FindingStatus } from './services/vulnerabilities'
import type { ConnectedRepository } from './services/repositories'
import { vulnerabilityService } from './services/vulnerabilities'
import { mergeIntelligenceService } from './services/mergeIntelligence'
import type { MergeAnalysis } from './services/mergeIntelligence'
import AuthCallbackPage from './pages/AuthCallbackPage'
import './App.css'

const VulnerabilityChart = lazy(
  () => import('./components/VulnerabilityChart'),
)

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
  const [notice, setNotice] = useState<{
    message: string
    kind: NoticeKind
  } | null>(null)

  const notify: Notify = (message, kind = 'info') => {
    setNotice({ message, kind })
  }

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
          {notice.kind === 'error' ? (
            <TriangleAlert size={17} />
          ) : notice.kind === 'success' ? (
            <CheckCircle2 size={17} />
          ) : (
            <Shield size={17} />
          )}

          <span>{notice.message}</span>

          <button
            className="icon-button toast-close"
            aria-label="Dismiss notification"
            onClick={() => setNotice(null)}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </NoticeContext.Provider>
  )
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <div className="brand-lockup">
      <div className="brand-mark">
        <Shield size={20} strokeWidth={2.2} />
        <span />
      </div>

      {!compact && (
        <div>
          <span className="brand-name">REPLOCK</span>
          <span className="brand-caption">SECURITY PLATFORM</span>
        </div>
      )}
    </div>
  )
}

function GithubMark({ size = 16 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.56.1.76-.24.76-.54v-2.1c-3.1.68-3.76-1.32-3.76-1.32-.5-1.3-1.24-1.65-1.24-1.65-1.02-.7.08-.69.08-.69 1.12.08 1.71 1.15 1.71 1.15 1 .1.75 2.24 3.78 1.59.1-.73.39-1.22.7-1.5-2.48-.28-5.08-1.24-5.08-5.52 0-1.22.44-2.21 1.15-2.99-.12-.28-.5-1.42.11-2.95 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.11-1.44 3.04-1.14 3.04-1.14.61 1.53.23 2.67.11 2.95.72.78 1.15 1.77 1.15 2.99 0 4.29-2.6 5.23-5.09 5.5.4.35.75 1.02.75 2.06v3.08c0 .3.2.65.77.54A11.1 11.1 0 0 0 12 .9Z" />
    </svg>
  )
}

function AppLayout() {
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const location = useLocation()

  const health = useQuery({
    queryKey: ['api-health'],
    queryFn: async () =>
      (await healthApi.get<{ status: string }>('/health')).data,
    retry: false,
    refetchInterval: 60000,
  })

  const account = useQuery({
    queryKey: ['current-user'],
    queryFn: authService.getCurrentUser,
    enabled: Boolean(authService.getAccessToken()),
    retry: false,
  })

  const title =
    navItems.find((item) => item.path === location.pathname)?.label ??
    'Settings'

  const username = account.data?.username ?? 'Not signed in'
  const initials =
    account.data?.username?.slice(0, 2).toUpperCase() ?? 'RL'

  return (
    <div className="app-shell">
      {mobileNavOpen && (
        <button
          className="mobile-scrim"
          aria-label="Close navigation"
          onClick={() => setMobileNavOpen(false)}
        />
      )}

      <aside className={`sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <Link to="/" className="brand-link" aria-label="RepLock overview">
          <Brand />
        </Link>

        <div className="workspace-switcher">
          <div className="workspace-avatar">R</div>
          <div className="workspace-copy">
            <strong>RepLock</strong>
            <span>Workspace</span>
          </div>
          <ChevronDown size={15} />
        </div>

        <div className="nav-section-label">WORKSPACE</div>

        <nav className="side-nav" aria-label="Main navigation">
          {navItems.map(({ label, path, icon: Icon }) => (
            <NavLink
              key={path}
              to={path}
              end={path === '/'}
              onClick={() => setMobileNavOpen(false)}
              className={({ isActive }) =>
                `nav-link ${isActive ? 'nav-active' : ''}`
              }
            >
              <Icon size={17} strokeWidth={1.8} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="nav-section-label tools-label">PREFERENCES</div>

        <NavLink
          to="/settings"
          onClick={() => setMobileNavOpen(false)}
          className={({ isActive }) =>
            `nav-link ${isActive ? 'nav-active' : ''}`
          }
        >
          <SlidersHorizontal size={17} strokeWidth={1.8} />
          <span>Settings</span>
        </NavLink>

        <div className="sidebar-bottom">
          <div className="connection-card">
            <div className="connection-heading">
              <GithubMark size={16} />
              <span>GitHub connection</span>
              <span
                className={`connection-dot ${account.isSuccess ? 'online' : ''}`}
              />
            </div>

            <p>
              {account.isSuccess
                ? `Connected as ${username}`
                : 'Not connected'}
            </p>

            <Link
              to={account.isSuccess ? '/repositories' : '/login'}
              className="connection-link"
            >
              {account.isSuccess ? 'View repositories' : 'Connect GitHub'}
              <ArrowRight size={13} />
            </Link>
          </div>

          <div className="agent-presence">
            <span
              className={`presence-pulse ${health.isSuccess ? '' : 'error-dot'}`}
            />
            <div>
              <strong>RepLock API</strong>
              <span>{health.isSuccess ? 'Connected' : 'Unavailable'}</span>
            </div>
            <MoreHorizontal size={17} />
          </div>

          <ProfileDropdown
            username={username}
            email={account.data?.email}
            initials={initials}
          />
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="Open navigation"
            onClick={() => setMobileNavOpen(true)}
          >
            <Menu size={19} />
          </button>

          <div className="topbar-breadcrumb">
            <span>Workspace</span>
            <ChevronRight size={14} />
            <strong>{title}</strong>
          </div>

          <div className="topbar-actions">
            <span className="preview-chip">
              <span className={health.isSuccess ? '' : 'error-dot'} />
              {health.isSuccess ? 'API CONNECTED' : 'API OFFLINE'}
            </span>

            <Link
              className="icon-button notification-button"
              aria-label="View security findings"
              title="View security findings"
              to="/vulnerabilities"
            >
              <Bell size={17} />
            </Link>

            <span className="topbar-divider" />

            <ProfileDropdown
              username={username}
              email={account.data?.email}
              initials={initials}
              compact
            />
          </div>
        </header>

        <main className="page-content">
          <Outlet />
        </main>

        <footer className="footer-note">
          <span>REPLOCK</span>
          <span>Secure every commit. Protect every merge.</span>
          <span>{health.isSuccess ? 'API connected' : 'API unavailable'}</span>
        </footer>
      </div>
    </div>
  )
}

function ProfileDropdown({
  username,
  email,
  initials,
  compact = false,
}: {
  username: string
  email?: string | null
  initials: string
  compact?: boolean
}) {
  const [open, setOpen] = useState(false)
  const [menuPosition, setMenuPosition] = useState<{ top: number; left: number } | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  useEffect(() => {
    if (!open) return

    const closeOutside = (event: PointerEvent) => {
      const target = event.target as Node
      if (
        !containerRef.current?.contains(target) &&
        !menuRef.current?.contains(target)
      ) {
        setOpen(false)
      }
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false)
        triggerRef.current?.focus()
        return
      }

      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return

      const items = Array.from(
        menuRef.current?.querySelectorAll<HTMLElement>(
          '[role="menuitem"]:not([aria-disabled="true"])',
        ) ?? [],
      )
      if (!items.length) return

      event.preventDefault()
      const currentIndex = items.indexOf(document.activeElement as HTMLElement)
      const direction = event.key === 'ArrowDown' ? 1 : -1
      const nextIndex =
        currentIndex < 0
          ? direction > 0
            ? 0
            : items.length - 1
          : (currentIndex + direction + items.length) % items.length
      items[nextIndex]?.focus()
    }

    document.addEventListener('pointerdown', closeOutside)
    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('pointerdown', closeOutside)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open])

  useLayoutEffect(() => {
    if (!open) return

    const updatePosition = () => {
      const trigger = triggerRef.current?.getBoundingClientRect()
      const menu = menuRef.current?.getBoundingClientRect()
      if (!trigger || !menu) return

      const top = compact
        ? trigger.bottom + 8
        : Math.max(8, trigger.top - menu.height - 8)
      const left = compact
        ? trigger.right - menu.width
        : trigger.left

      setMenuPosition({
        top: Math.min(top, window.innerHeight - menu.height - 8),
        left: Math.max(8, Math.min(left, window.innerWidth - menu.width - 8)),
      })
    }

    updatePosition()
    menuRef.current
      ?.querySelector<HTMLElement>('[role="menuitem"]')
      ?.focus()
    window.addEventListener('resize', updatePosition)
    window.addEventListener('scroll', updatePosition, true)

    return () => {
      window.removeEventListener('resize', updatePosition)
      window.removeEventListener('scroll', updatePosition, true)
    }
  }, [open, compact])

  const signOut = () => {
    authService.clearAccessToken()
    queryClient.clear()
    navigate('/login', { replace: true })
  }

  return (
    <div
      className={`profile-menu-wrap ${compact ? 'profile-menu-header' : ''}`}
      ref={containerRef}
    >
      <button
        ref={triggerRef}
        className={compact ? 'topbar-user' : 'profile-button'}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={compact ? 'profile-menu-header' : 'profile-menu-sidebar'}
        aria-label={`Profile menu for ${username}`}
        onClick={() => setOpen((value) => !value)}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' && !open) {
            event.preventDefault()
            setOpen(true)
          }
        }}
      >
        <div className="profile-avatar">{initials}</div>
        {!compact && (
          <div className="profile-copy">
            <strong>{username}</strong>
            <span>{email || 'GitHub account'}</span>
          </div>
        )}
        <ChevronDown size={compact ? 14 : 15} />
      </button>

      {open &&
        createPortal(
          <div
            className="profile-menu"
            id={compact ? 'profile-menu-header' : 'profile-menu-sidebar'}
            role="menu"
            aria-label="Profile"
            ref={menuRef}
            style={
              menuPosition
                ? { top: menuPosition.top, left: menuPosition.left, visibility: 'visible' }
                : undefined
            }
          >
            <div className="profile-menu-account">
              <strong>{username}</strong>
              {email && <span>{email}</span>}
            </div>
            <Link
              to="/settings"
              role="menuitem"
              onClick={() => setOpen(false)}
            >
              <SlidersHorizontal size={15} />
              Settings
            </Link>
            <button type="button" role="menuitem" onClick={signOut}>
              <LogOut size={15} />
              Sign out
            </button>
          </div>,
          document.body,
        )}
    </div>
  )
}

function RequireAuth() {
  const location = useLocation()
  const token = authService.getAccessToken()
  const account = useQuery({
    queryKey: ['current-user'],
    queryFn: authService.getCurrentUser,
    enabled: Boolean(token),
    retry: false,
  })

  if (!token) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }

  if (account.isLoading) {
    return (
      <div className="panel empty-state">
        <LoaderCircle size={20} className="spin" />
        <strong>Verifying your session</strong>
      </div>
    )
  }

  if (account.isError) {
    return (
      <div className="login-page">
        <section className="panel empty-state">
          <TriangleAlert size={20} />
          <strong>Unable to verify your session</strong>
          <span>{getApiErrorMessage(account.error)}</span>
          <Button variant="secondary" onClick={() => void account.refetch()}>
            <RefreshCw size={14} /> Retry
          </Button>
          <Link className="text-link" to="/login">
            Return to sign in
          </Link>
        </section>
      </div>
    )
  }

  return <Outlet />
}

function PageHeading({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow?: string
  title: string
  description: string
  actions?: ReactNode
}) {
  return (
    <div className="page-heading">
      <div>
        {eyebrow && <div className="eyebrow">{eyebrow}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>

      {actions && <div className="heading-actions">{actions}</div>}
    </div>
  )
}

function Button({
  children,
  variant = 'primary',
  onClick,
  type = 'button',
  disabled = false,
  className = '',
}: {
  children: ReactNode
  variant?: 'primary' | 'secondary' | 'quiet' | 'danger'
  onClick?: () => void
  type?: 'button' | 'submit'
  disabled?: boolean
  className?: string
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`button inline-flex items-center justify-center gap-2 transition-colors disabled:cursor-not-allowed button-${variant} ${className}`}
    >
      {children}
    </button>
  )
}

function StatusBadge({
  children,
  tone = 'neutral',
}: {
  children: ReactNode
  tone?: 'neutral' | 'success' | 'danger' | 'warning' | 'purple'
}) {
  return (
    <span className={`status-badge badge-${tone}`}>
      <span className="status-dot" />
      {children}
    </span>
  )
}

function Modal({
  title,
  onClose,
  children,
  wide = false,
}: {
  title: string
  onClose: () => void
  children: ReactNode
  wide?: boolean
}) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose()
      }}
    >
      <section
        className={`modal-card ${wide ? 'modal-wide' : ''}`}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-header">
          <h2>{title}</h2>
          <button
            className="icon-button"
            aria-label="Close dialog"
            onClick={onClose}
          >
            <X size={17} />
          </button>
        </div>

        <div className="modal-body">{children}</div>
      </section>
    </div>
  )
}

function MetricCard({
  label,
  value,
  icon,
  detail,
  detailTone,
  alert = false,
}: {
  label: string
  value: string
  icon: ReactNode
  detail: string
  detailTone?: 'positive' | 'negative'
  alert?: boolean
}) {
  return (
    <div className={`metric-card ${alert ? 'metric-alert' : ''}`}>
      <div className="metric-top">
        <span>{label}</span>
        <span className={`metric-icon ${alert ? 'metric-icon-alert' : ''}`}>
          {icon}
        </span>
      </div>

      <div className="metric-value">{value}</div>

      <div className={`metric-detail ${detailTone ?? ''}`}>
        {detailTone === 'positive' ? (
          <ArrowDownRight size={13} />
        ) : detailTone === 'negative' ? (
          <ArrowUpRight size={13} />
        ) : (
          <span className="metric-detail-dot" />
        )}
        {detail}
      </div>
    </div>
  )
}

function PanelHeading({
  title,
  subtitle,
  action,
}: {
  title: string
  subtitle: string
  action?: ReactNode
}) {
  return (
    <div className="panel-heading">
      <div>
        <h2>{title}</h2>
        <p>{subtitle}</p>
      </div>
      {action}
    </div>
  )
}

function ActivityItem({
  icon,
  tone,
  title,
  detail,
  time,
}: {
  icon: ReactNode
  tone: string
  title: string
  detail: string
  time: string
}) {
  return (
    <div className="activity-item">
      <div className={`activity-icon activity-${tone}`}>{icon}</div>
      <div className="activity-copy">
        <strong>{title}</strong>
        <span>{detail}</span>
      </div>
      <time>{time}</time>
    </div>
  )
}

function SeverityPill({ severity }: { severity: string }) {
  return (
    <span className={`severity-pill severity-${severity.toLowerCase()}`}>
      {severity}
    </span>
  )
}

function formatDate(value?: string | null) {
  return value ? new Date(value).toLocaleString() : '—'
}

function formatStatus(status: string) {
  return status.replaceAll('_', ' ')
}

function OverviewPage() {
  const navigate = useNavigate()

  const overview = useQuery({
    queryKey: ['dashboard-overview'],
    queryFn: dashboardService.overview,
    retry: false,
  })

  const trends = useQuery({
    queryKey: ['dashboard-trends', 30],
    queryFn: () => dashboardService.trends(30),
    retry: false,
  })

  const data = overview.data
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']

  const severityPalette: Record<string, string> = {
    critical: '#ef6464',
    high: '#f39a55',
    medium: '#e9c45d',
    low: '#6ca7e8',
    info: '#9b8be8',
  }

  const chartData = severityOrder
    .map((name) => ({
      name: name[0].toUpperCase() + name.slice(1),
      value: data?.findings_by_severity?.[name] ?? 0,
      color: severityPalette[name],
    }))
    .filter((item) => item.value > 0)

  const riskTone =
    data?.risk_level === 'critical' || data?.risk_level === 'high'
      ? 'danger'
      : data?.risk_level === 'moderate'
        ? 'warning'
        : 'success'

  return (
    <>
      <PageHeading
        eyebrow="SECURITY OPERATIONS"
        title="Security overview"
        description="Live security posture and recent activity across your connected repositories."
        actions={
          <Button onClick={() => navigate('/scans')}>
            <Plus size={16} />
            New security scan
          </Button>
        }
      />

      <section className="welcome-banner">
        <div className="welcome-icon">
          <ShieldCheck size={23} />
        </div>

        <div className="welcome-copy">
          <div className="welcome-label">
            <span
              className={`live-dot ${overview.isSuccess ? '' : 'error-dot'}`}
            />
            {overview.isSuccess
              ? 'LIVE PLATFORM DATA'
              : overview.isLoading
                ? 'LOADING PLATFORM DATA'
                : 'PLATFORM DATA UNAVAILABLE'}
            <span className="welcome-separator">·</span>
            {overview.isSuccess ? 'API CONNECTED' : 'API STATUS UNKNOWN'}
          </div>

          <h2>Your code, under a closer watch.</h2>
          <p>
            Track repository security, review findings and act on risks
            detected by RepLock.
          </p>
        </div>

        <Button
          variant="secondary"
          onClick={() => navigate('/repositories')}
        >
          Manage repositories <ArrowRight size={15} />
        </Button>

        <div className="banner-grid" aria-hidden="true" />
      </section>

      {overview.isLoading ? (
        <div className="panel empty-state">
          <LoaderCircle size={20} className="spin" />
          <strong>Loading security overview</strong>
          <span>Fetching current dashboard data…</span>
        </div>
      ) : overview.isError ? (
        <div className="callout callout-warning">
          <TriangleAlert size={17} />
          <span>{getApiErrorMessage(overview.error)}</span>
          <Button
            variant="secondary"
            onClick={() => void overview.refetch()}
          >
            <RefreshCw size={14} /> Retry
          </Button>
        </div>
      ) : data ? (
        <>
          <section className="metric-grid" aria-label="Security metrics">
            <MetricCard
              label="Connected repositories"
              value={String(data.total_repositories)}
              icon={<Code2 size={17} />}
              detail="Connected GitHub repositories"
            />

            <MetricCard
              label="Total scans"
              value={String(data.total_scans)}
              icon={<Activity size={17} />}
              detail={`${data.scan_status_counts?.completed ?? 0} completed`}
            />

            <MetricCard
              label="Open findings"
              value={String(data.findings_by_status?.open ?? 0)}
              icon={<ShieldAlert size={17} />}
              detail={`${data.total_findings} total findings`}
            />

            <MetricCard
              label="Security score"
              value={`${data.security_score}/100`}
              icon={<ShieldCheck size={17} />}
              detail={`${data.risk_points} risk points`}
              detailTone={data.risk_points ? 'negative' : 'positive'}
              alert={data.risk_level === 'critical'}
            />
          </section>

          <div className="overview-grid">
            <section className="panel recent-scans-panel">
              <PanelHeading
                title="Recent security scans"
                subtitle="Latest completed and in-progress assessments"
                action={
                  <button
                    className="text-link"
                    onClick={() => navigate('/scans')}
                  >
                    Run scan <ArrowRight size={14} />
                  </button>
                }
              />

              <div className="scan-list">
                {data.recent_scans.length ? (
                  data.recent_scans.slice(0, 5).map((scan) => (
                    <div className="scan-list-row" key={scan.scan_id}>
                      <div className="scan-repo-icon">
                        {scan.repository_name.charAt(0).toUpperCase()}
                      </div>

                      <div className="scan-list-main">
                        <strong>{scan.repository_name}</strong>
                        <span>
                          <GitBranch size={12} /> {scan.scan_type}
                          <span className="scan-separator">·</span>
                          {scan.commit_sha?.slice(0, 8) ||
                            'Commit unavailable'}
                        </span>
                      </div>

                      <div className="scan-findings">
                        <b>{scan.findings_count}</b>
                        <span> findings</span>
                      </div>

                      <StatusBadge
                        tone={
                          scan.status === 'completed'
                            ? 'success'
                            : scan.status === 'failed'
                              ? 'danger'
                              : 'warning'
                        }
                      >
                        {formatStatus(scan.status)}
                      </StatusBadge>

                      <div className="scan-date">
                        {formatDate(scan.created_at)}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <Activity size={19} />
                    <strong>No scans yet</strong>
                    <span>Run your first repository security scan.</span>
                  </div>
                )}
              </div>
            </section>

            <section className="panel distribution-panel">
              <PanelHeading
                title="Vulnerability distribution"
                subtitle={`${data.total_findings} findings across connected repositories`}
              />

              <div className="chart-wrap">
                <Suspense
                  fallback={
                    <div className="chart-loading">
                      <LoaderCircle size={15} className="spin" />
                      Loading chart…
                    </div>
                  }
                >
                  <VulnerabilityChart data={chartData} />
                </Suspense>

                <div className="chart-center">
                  <strong>{data.total_findings}</strong>
                  <span>total findings</span>
                </div>
              </div>

              <div className="chart-legend">
                {severityOrder.map((name) => (
                  <div key={name}>
                    <i style={{ background: severityPalette[name] }} />
                    <span>
                      {name[0].toUpperCase() + name.slice(1)}
                    </span>
                    <strong>
                      {data.findings_by_severity?.[name] ?? 0}
                    </strong>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <div className="overview-grid lower-grid">
            <section className="panel repo-status-panel">
              <PanelHeading
                title="Most affected files"
                subtitle="Files with the highest number of recorded findings"
                action={
                  <button
                    className="text-link"
                    onClick={() => navigate('/vulnerabilities')}
                  >
                    View findings <ArrowRight size={14} />
                  </button>
                }
              />

              <div className="repo-status-list">
                {data.most_affected_files.length ? (
                  data.most_affected_files.slice(0, 5).map((file) => (
                    <div className="repo-status-row" key={file.file_path}>
                      <div className="repo-mini-icon">
                        <FileCode2 size={14} />
                      </div>

                      <div className="repo-status-name">
                        <strong>{file.file_path}</strong>
                        <span>{file.repository_count} repositories</span>
                      </div>

                      <StatusBadge tone="warning">
                        {file.finding_count} findings
                      </StatusBadge>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <CheckCircle2 size={18} />
                    <strong>No affected files reported</strong>
                  </div>
                )}
              </div>
            </section>

            <section className="panel activity-panel">
              <PanelHeading
                title="Security posture"
                subtitle="Current risk assessment"
              />

              <div className="activity-list">
                <ActivityItem
                  icon={<ShieldCheck size={14} />}
                  tone="green"
                  title={`Security score: ${data.security_score}/100`}
                  detail="Calculated from recorded repository findings"
                  time={data.risk_level.toUpperCase()}
                />

                <ActivityItem
                  icon={<AlertTriangle size={14} />}
                  tone="red"
                  title={`${data.risk_points} risk points`}
                  detail={`${data.findings_by_status?.open ?? 0} findings currently open`}
                  time={data.risk_level}
                />

                <ActivityItem
                  icon={<Clock3 size={14} />}
                  tone="purple"
                  title="Latest scan"
                  detail={data.latest_scan?.repository_name ?? 'No scans recorded'}
                  time={formatDate(data.latest_scan?.created_at)}
                />
              </div>

              <div className="mt-3">
                <StatusBadge tone={riskTone}>
                  {data.risk_level.toUpperCase()} RISK
                </StatusBadge>
              </div>
            </section>
          </div>

          <section className="panel trend-panel">
            <PanelHeading
              title="Security activity"
              subtitle="Stored scan and finding trends over the last 30 days"
            />

            {trends.isLoading ? (
              <div className="empty-state">
                <LoaderCircle size={18} className="spin" />
                Loading security trends…
              </div>
            ) : trends.isError ? (
              <div className="callout callout-warning">
                <TriangleAlert size={16} />
                {getApiErrorMessage(trends.error)}
                <Button
                  variant="secondary"
                  onClick={() => void trends.refetch()}
                >
                  <RefreshCw size={14} /> Retry
                </Button>
              </div>
            ) : trends.data?.length ? (
              <div className="trend-list">
                {trends.data.slice(-7).map((point) => (
                  <div className="trend-row" key={point.date}>
                    <time>
                      {new Date(`${point.date}T00:00:00`).toLocaleDateString()}
                    </time>
                    <span>{point.scans} scans</span>
                    <span>{point.findings} findings</span>
                    <span className="trend-risk">
                      {point.critical} critical · {point.high} high
                    </span>
                    <StatusBadge tone={point.unresolved ? 'warning' : 'success'}>
                      {point.unresolved} unresolved
                    </StatusBadge>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                <Activity size={18} />
                <strong>No scan activity in this period</strong>
                <span>Trend data appears after a scan is recorded.</span>
              </div>
            )}
          </section>
        </>
      ) : null}
    </>
  )
}
function RepositoriesPage() {
  const [needsAttentionOnly, setNeedsAttentionOnly] = useState(false)
  const [githubPage, setGithubPage] = useState(1)
  const notify = useNotify()
  const queryClient = useQueryClient()
  const githubPageSize = 30

  const githubRepos = useQuery({
    queryKey: ['github-repositories', githubPage],
    queryFn: () => repositoryService.listGithub(githubPage, githubPageSize),
    enabled: Boolean(authService.getAccessToken()),
    retry: false,
  })

  const connectedRepos = useQuery({
    queryKey: ['connected-repositories'],
    queryFn: repositoryService.listConnected,
    enabled: Boolean(authService.getAccessToken()),
    retry: false,
  })

  const connect = useMutation({
    mutationFn: repositoryService.connect,
    onSuccess: async (repo) => {
      await Promise.all([
        connectedRepos.refetch(),
        queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] }),
      ])
      notify(`${repo.full_name} connected successfully.`, 'success')
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })

  if (!authService.getAccessToken()) {
    return (
      <>
        <PageHeading
          eyebrow="YOUR CODEBASE"
          title="Repositories"
          description="Connect your GitHub account to import repositories."
        />
        <section className="panel empty-state">
          <GithubMark size={26} />
          <strong>Connect your GitHub account</strong>
          <span>Sign in with GitHub to view and connect repositories you own.</span>
          <Link className="button button-primary" to="/login">
            <GithubMark size={15} /> Connect GitHub
          </Link>
        </section>
      </>
    )
  }

  const connectedIds = new Set(
    (connectedRepos.data ?? []).map((repo) => repo.github_repo_id),
  )

  const visibleRepos = (githubRepos.data ?? []).filter((repo) => {
    if (!needsAttentionOnly) return true
    return !connectedIds.has(repo.github_repo_id)
  })

  return (
    <>
      <PageHeading
        eyebrow="YOUR CODEBASE"
        title="Repositories"
        description="Manage connected repositories and review your GitHub repositories."
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              void githubRepos.refetch()
              void connectedRepos.refetch()
            }}
          >
            <RefreshCw size={15} /> Refresh
          </Button>
        }
      />

      <section className="panel table-panel">
        <div className="table-toolbar">
          <div>
            <strong>{visibleRepos.length} repositories on this page</strong>
            <span> · {connectedIds.size} connected to RepLock</span>
          </div>

          <button
            className={`filter-button ${needsAttentionOnly ? 'filter-active' : ''}`}
            aria-pressed={needsAttentionOnly}
            onClick={() => setNeedsAttentionOnly((current) => !current)}
          >
            <SlidersHorizontal size={15} />
            {needsAttentionOnly ? 'Showing unconnected' : 'Show unconnected'}
          </button>
        </div>

        {githubRepos.isLoading || connectedRepos.isLoading ? (
          <div className="empty-state">
            <LoaderCircle size={20} className="spin" />
            <strong>Loading repositories</strong>
            <span>Fetching your GitHub repositories…</span>
          </div>
        ) : githubRepos.isError || connectedRepos.isError ? (
          <div className="callout callout-warning">
            <TriangleAlert size={17} />
            <span>
              {getApiErrorMessage(githubRepos.error ?? connectedRepos.error)}
            </span>
            <Button
              variant="secondary"
              onClick={() => {
                void githubRepos.refetch()
                void connectedRepos.refetch()
              }}
            >
              <RefreshCw size={14} /> Retry
            </Button>
          </div>
        ) : visibleRepos.length === 0 ? (
          <div className="empty-state">
            <Code2 size={20} />
            <strong>No repositories found</strong>
            <span>There are no repositories matching this filter.</span>
          </div>
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>REPOSITORY</th>
                  <th>LANGUAGE</th>
                  <th>DEFAULT BRANCH</th>
                  <th>VISIBILITY</th>
                  <th>UPDATED</th>
                  <th>CONNECTION</th>
                  <th />
                </tr>
              </thead>

              <tbody>
                {visibleRepos.map((repo) => {
                  const isConnected = connectedIds.has(repo.github_repo_id)

                  return (
                    <tr key={repo.github_repo_id}>
                      <td>
                        <div className="repo-cell">
                          <div className="repo-mini-icon">
                            {repo.name.charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <strong>{repo.full_name}</strong>
                            <span>
                              {repo.description || 'No description provided'}
                            </span>
                          </div>
                        </div>
                      </td>

                      <td>
                        <span className="language-label">
                          {repo.language || '—'}
                        </span>
                      </td>

                      <td>
                        <span className="branch-label">
                          <GitBranch size={13} />
                          {repo.default_branch}
                        </span>
                      </td>

                      <td>
                        <span className="muted-cell">
                          {repo.is_private ? 'Private' : 'Public'}
                        </span>
                      </td>

                      <td className="muted-cell">
                        {repo.updated_at
                          ? new Date(repo.updated_at).toLocaleDateString()
                          : '—'}
                      </td>

                      <td>
                        <StatusBadge tone={isConnected ? 'success' : 'neutral'}>
                          {isConnected ? 'Connected' : 'Not connected'}
                        </StatusBadge>
                      </td>

                      <td>
                        {isConnected ? (
                          <Button variant="quiet" disabled>
                            Connected
                          </Button>
                        ) : (
                          <Button
                            variant="secondary"
                            disabled={connect.isPending}
                            onClick={() =>
                              connect.mutate(repo.github_repo_id)
                            }
                          >
                            {connect.isPending ? (
                              <LoaderCircle size={14} className="spin" />
                            ) : (
                              <Plus size={14} />
                            )}
                            Connect
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="pagination-row">
          <span>GitHub repository page {githubPage}</span>
          <div>
            <Button
              variant="secondary"
              disabled={githubPage === 1 || githubRepos.isFetching}
              onClick={() => setGithubPage((page) => page - 1)}
            >
              Previous
            </Button>
            <Button
              variant="secondary"
              disabled={
                githubRepos.isFetching ||
                (githubRepos.data?.length ?? 0) < githubPageSize
              }
              onClick={() => setGithubPage((page) => page + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      </section>
    </>
  )
}

function Detail({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="detail-item">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function ScanningPage() {
  const notify = useNotify()
  const queryClient = useQueryClient()
  const [repositoryId, setRepositoryId] = useState('')
  const [scanType, setScanType] = useState<'full' | 'static'>('full')
  const [scanIssue, setScanIssue] = useState<{
    message: string
    status: 'failed' | 'unknown' | 'completed'
  } | null>(null)
  const [pendingScan, setPendingScan] = useState<{
    scanId?: string
    repositoryId: string
    repositoryName: string
    requestedAt: number
  } | null>(null)
  const scanAttemptRef = useRef<{
    scanId?: string
    repositoryId: string
    repositoryName: string
    requestedAt: number
  } | null>(null)
  const recoveringScanRef = useRef<string | null>(null)
  const [result, setResult] = useState<{
    scan: ScanRunResult
    repositoryName: string
  } | null>(null)

  const repos = useQuery({
    queryKey: ['connected-repositories'],
    queryFn: repositoryService.listConnected,
    enabled: Boolean(authService.getAccessToken()),
    retry: false,
  })

  const history = useQuery({
    queryKey: ['scan-history'],
    queryFn: scanService.list,
    enabled: Boolean(authService.getAccessToken()),
    refetchInterval: (query) => {
      const hasUntrackedActiveScan = Boolean(
        query.state.data?.some(
          (scan) =>
            scan.id !== pendingScan?.scanId &&
            (scan.status === 'pending' || scan.status === 'running'),
        ),
      )
      return Boolean(pendingScan && !pendingScan.scanId) ||
        hasUntrackedActiveScan
        ? 5000
        : false
    },
  })

  const pendingStatus = useQuery({
    queryKey: ['scan-status', pendingScan?.scanId],
    queryFn: () => {
      if (!pendingScan?.scanId) {
        throw new Error('A scan ID is required to fetch scan status.')
      }
      return scanService.get(pendingScan.scanId)
    },
    enabled: Boolean(pendingScan?.scanId),
    refetchInterval: (query) =>
      pendingScan &&
      query.state.data?.status !== 'completed' &&
      query.state.data?.status !== 'failed'
        ? 5000
        : false,
  })

  const pendingScanCandidates = pendingScan?.scanId
    ? pendingStatus.data
      ? [pendingStatus.data]
      : []
    : history.data ?? []
  const pendingScanRecord = pendingScan
    ? pendingScanCandidates
        .filter(
          (scan) =>
            scan.id === pendingScan.scanId ||
            (scan.repository_id === pendingScan.repositoryId &&
              Date.parse(scan.created_at) >= pendingScan.requestedAt),
        )
        .sort(
          (left, right) =>
            Date.parse(right.created_at) - Date.parse(left.created_at),
        )[0]
    : undefined
  const pendingScanFailed = pendingScanRecord?.status === 'failed'
  const visibleScanIssue = pendingScanFailed
    ? {
        message:
          pendingScanRecord.summary ||
          'The failed scan did not include additional error details.',
        status: 'failed' as const,
      }
    : scanIssue

  const recoverCompletedScan = useCallback(async (
    scan: ScanRecord,
    repositoryName: string,
  ) => {
    try {
      const findings = await vulnerabilityService.listAllForScan(scan.id)
      setResult({
        repositoryName,
        scan: {
          scan,
          findings,
          semgrep_findings: scan.semgrep_findings ?? null,
          files_analyzed: scan.files_analyzed ?? null,
          limitations: scan.limitations ?? null,
        },
      })
      setScanIssue(null)
      setPendingScan(null)
      notify(
        'The completed scan was recovered from persisted scan history.',
        'success',
      )
      void Promise.allSettled([
        queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard-trends'] }),
        queryClient.invalidateQueries({ queryKey: ['findings'] }),
        queryClient.invalidateQueries({ queryKey: ['finding-summary'] }),
      ])
    } catch (error) {
      setScanIssue({
        message: `The scan completed and was saved, but its findings could not be loaded: ${getApiErrorMessage(error)}`,
        status: 'completed',
      })
      setPendingScan(null)
    } finally {
      recoveringScanRef.current = null
      void queryClient.invalidateQueries({ queryKey: ['scan-history'] })
    }
  }, [notify, queryClient])

  useEffect(() => {
    if (!pendingScan) return

    const scan = (pendingStatus.data
      ? [pendingStatus.data]
      : history.data ?? [])
      .filter(
        (item) =>
          pendingScan.scanId
            ? item.id === pendingScan.scanId
            : item.repository_id === pendingScan.repositoryId &&
              Date.parse(item.created_at) >= pendingScan.requestedAt,
      )
      .sort(
        (left, right) =>
          Date.parse(right.created_at) - Date.parse(left.created_at),
      )[0]

    if (!scan || scan.status === 'pending' || scan.status === 'running') return

    if (scan.status === 'completed') {
      if (recoveringScanRef.current === scan.id) return
      recoveringScanRef.current = scan.id
      void recoverCompletedScan(scan, pendingScan.repositoryName)
    }
  }, [history.data, pendingStatus.data, pendingScan, recoverCompletedScan])

  const runScan = useMutation({
    mutationFn: () => scanService.start(repositoryId, scanType),
    onSuccess: (data) => {
      const repo = repos.data?.find((item) => item.id === repositoryId)
      scanAttemptRef.current = null

      const attempt = {
        scanId: data.id,
        repositoryId: data.repository_id,
        repositoryName: repo?.full_name ?? 'Connected repository',
        requestedAt: Date.parse(data.created_at),
      }
      setPendingScan(attempt)
      setScanIssue(null)
      notify('Security scan queued. RepLock will track its progress.', 'success')
      void Promise.allSettled([
        history.refetch(),
        queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard-trends'] }),
      ])
    },
    onError: async (error) => {
      const attempt = scanAttemptRef.current
      scanAttemptRef.current = null
      const refreshedHistory = await history.refetch()
      const matchingScan = attempt
        ? refreshedHistory.data
            ?.filter(
              (scan) =>
                (attempt.scanId
                  ? scan.id === attempt.scanId
                  : scan.repository_id === attempt.repositoryId &&
                    Date.parse(scan.created_at) >= attempt.requestedAt),
            )
            .sort(
              (left, right) =>
                Date.parse(right.created_at) - Date.parse(left.created_at),
            )[0]
        : undefined

      if (
        (matchingScan?.status === 'pending' ||
          matchingScan?.status === 'running') &&
        attempt
      ) {
        setPendingScan({
          ...attempt,
          scanId: matchingScan.id,
          requestedAt: Date.parse(matchingScan.created_at),
        })
        setScanIssue({
          message:
            'The request did not return a confirmation, but the scan is recorded on the server. RepLock will continue checking its status.',
          status: 'unknown',
        })
        notify('Scan status is being checked in scan history.', 'info')
      } else if (matchingScan?.status === 'completed' && attempt) {
        await recoverCompletedScan(matchingScan, attempt.repositoryName)
      } else if (matchingScan?.status === 'failed') {
        setScanIssue({
          message: matchingScan.summary || getApiErrorMessage(error),
          status: 'failed',
        })
        notify(matchingScan.summary || getApiErrorMessage(error), 'error')
      } else if (isScanRequestTimeout(error) && attempt) {
        setPendingScan(attempt)
        setScanIssue({
          message:
            'The request timed out before the API confirmed whether it accepted the scan. RepLock will check history before allowing another scan.',
          status: 'unknown',
        })
        notify('Scan outcome is being checked in scan history.', 'info')
      } else {
        const message = getApiErrorMessage(error)
        setScanIssue({ message, status: 'failed' })
        notify(message, 'error')
      }

      void Promise.allSettled([
        queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] }),
      ])
    },
  })

  const activeScan = history.data?.find(
    (scan) =>
      scan.repository_id === repositoryId &&
      scan.id !== pendingScan?.scanId &&
      (scan.status === 'pending' || scan.status === 'running'),
  )

  const startScan = () => {
    if (
      !repositoryId ||
      runScan.isPending ||
      (pendingScan && !pendingScanFailed) ||
      activeScan ||
      scanAttemptRef.current
    ) {
      return
    }

    const repo = repos.data?.find((item) => item.id === repositoryId)
    setPendingScan(null)
    scanAttemptRef.current = {
      repositoryId,
      repositoryName: repo?.full_name ?? 'Connected repository',
      requestedAt: Date.now(),
    }
    setResult(null)
    setScanIssue(null)
    runScan.mutate()
  }

  const refreshScanStatus = async () => {
    if (!pendingScan) return
    let scanRecords: ScanRecord[]
    if (pendingScan.scanId) {
      const refreshedStatus = await pendingStatus.refetch()
      scanRecords = refreshedStatus.data ? [refreshedStatus.data] : []
    } else {
      const refreshedHistory = await history.refetch()
      scanRecords = refreshedHistory.data ?? []
    }

    const scan = scanRecords
      .filter(
        (item) =>
          pendingScan.scanId
            ? item.id === pendingScan.scanId
            : item.repository_id === pendingScan.repositoryId &&
              Date.parse(item.created_at) >= pendingScan.requestedAt,
      )
      .sort(
        (left, right) =>
          Date.parse(right.created_at) - Date.parse(left.created_at),
      )[0]
    if (!scan) {
      setPendingScan(null)
      setScanIssue({
        message:
          'No scan record was created for the request. It is now safe to retry.',
        status: 'failed',
      })
      return
    }

    if (scan.status === 'failed') {
      setPendingScan(null)
      setScanIssue({
        message: scan.summary || 'The security scan failed.',
        status: 'failed',
      })
    }
    if (scan.status === 'completed') {
      if (recoveringScanRef.current === scan.id) return
      recoveringScanRef.current = scan.id
      await recoverCompletedScan(scan, pendingScan.repositoryName)
    }
  }

  if (!authService.getAccessToken()) {
    return (
      <>
        <PageHeading
          eyebrow="SECURITY ENGINE"
          title="Security scans"
          description="Connect GitHub before running repository security assessments."
        />
        <section className="panel empty-state">
          <GithubMark size={26} />
          <strong>GitHub authentication required</strong>
          <span>Connect your account to scan your repositories.</span>
          <Link className="button button-primary" to="/login">
            Connect GitHub
          </Link>
        </section>
      </>
    )
  }

  const selectedRepo = repos.data?.find(
    (repo) => repo.id === repositoryId,
  )

  return (
    <>
      <PageHeading
        eyebrow="SECURITY ENGINE"
        title="Security scans"
        description="Run security assessments against your connected GitHub repositories."
      />

      <section className="panel scan-config-panel">
        <PanelHeading
          title="Configure assessment"
          subtitle="Choose a connected repository and scan type."
        />

        {repos.isLoading ? (
          <div className="empty-state">
            <LoaderCircle size={18} className="spin" />
            Loading repositories…
          </div>
        ) : repos.isError ? (
          <div className="callout callout-warning">
            <TriangleAlert size={16} />
            {getApiErrorMessage(repos.error)}
          </div>
        ) : repos.data?.length ? (
          <>
            <div className="form-grid">
              <div className="form-field">
                <label className="field-label" htmlFor="scan-repository">
                  Repository
                </label>
                <div className="select-wrap">
                  <select
                    id="scan-repository"
                    value={repositoryId}
                    disabled={
                      runScan.isPending ||
                      Boolean(pendingScan && !pendingScanFailed)
                    }
                    onChange={(event) => {
                      setRepositoryId(event.target.value)
                      setResult(null)
                      setScanIssue(null)
                    }}
                  >
                    <option value="">Select repository</option>
                    {repos.data.map((repo) => (
                      <option key={repo.id} value={repo.id}>
                        {repo.full_name}
                      </option>
                    ))}
                  </select>
                  <ChevronDown size={14} />
                </div>
              </div>

              <div className="form-field">
                <label className="field-label" htmlFor="scan-type">
                  Scan type
                </label>
                <div className="select-wrap">
                  <select
                    id="scan-type"
                    value={scanType}
                    disabled={
                      runScan.isPending ||
                      Boolean(pendingScan && !pendingScanFailed)
                    }
                    onChange={(event) => {
                      setScanType(event.target.value as 'full' | 'static')
                      setResult(null)
                      setScanIssue(null)
                    }}
                  >
                    <option value="full">Full security scan</option>
                    <option value="static">Static analysis</option>
                  </select>
                  <ChevronDown size={14} />
                </div>
              </div>
            </div>

            <div className="scan-config-footer">
              <div className="scan-branch-info">
                <span className="scan-branch-icon">
                  <ShieldCheck size={17} />
                </span>
                <div className="scan-branch-copy">
                  <span className="scan-branch-label">
                    Default branch
                  </span>
                  <strong>
                    {selectedRepo
                      ? selectedRepo.default_branch
                      : 'Select a repository to begin'}
                  </strong>
                </div>
              </div>

              <Button
                disabled={
                  !repositoryId ||
                  runScan.isPending ||
                  Boolean(pendingScan && !pendingScanFailed) ||
                  Boolean(activeScan)
                }
                onClick={startScan}
              >
                {runScan.isPending ? (
                  <LoaderCircle size={15} className="spin" />
                ) : (
                  <Play size={15} />
                )}
                {runScan.isPending ? 'Scanning…' : 'Run security scan'}
              </Button>
            </div>
          </>
        ) : (
          <div className="empty-state">
            <Code2 size={20} />
            <strong>No connected repositories</strong>
            <span>Connect a repository before starting a scan.</span>
            <Link className="text-link" to="/repositories">
              Manage repositories <ArrowRight size={14} />
            </Link>
          </div>
        )}
        {activeScan && (
          <div className="callout callout-info scan-active">
            <LoaderCircle size={16} className="spin" />
            <span>
              A scan for this repository is already running. Refresh history
              for its latest status.
            </span>
            <Button
              variant="secondary"
              onClick={() => void history.refetch()}
            >
              <RefreshCw size={14} /> Refresh
            </Button>
          </div>
        )}
      </section>

      {visibleScanIssue && (
        <div
          className={`callout ${visibleScanIssue.status === 'unknown' ? 'callout-info' : 'callout-warning'} scan-error`}
          role="alert"
        >
          {visibleScanIssue.status === 'unknown' ? (
            <LoaderCircle size={16} className="spin" />
          ) : visibleScanIssue.status === 'completed' ? (
            <CheckCircle2 size={16} />
          ) : (
            <TriangleAlert size={16} />
          )}
          <span>{visibleScanIssue.message}</span>
          <Button
            variant="secondary"
            disabled={runScan.isPending}
            onClick={() =>
              visibleScanIssue.status === 'failed' &&
              (!pendingScan || pendingScanFailed)
                ? startScan()
                : void refreshScanStatus()
            }
          >
            <RefreshCw size={14} />
            {visibleScanIssue.status === 'failed' &&
            (!pendingScan || pendingScanFailed)
              ? 'Retry scan'
              : 'Refresh status'}
          </Button>
        </div>
      )}

      {(runScan.isPending || Boolean(pendingScan && !pendingScanFailed)) && (
        <section className="panel scan-progress-panel">
          <div className="scan-progress-heading">
            <LoaderCircle size={19} className="spin" />
            <div>
              <strong>Security assessment running</strong>
              <span>
                The backend is analyzing the selected repository. This may take
                a little while.
              </span>
            </div>
          </div>
        </section>
      )}

      {result && (
        <section className="panel scan-result-panel">
          <PanelHeading
            title="Scan results"
            subtitle={`${result.repositoryName} · ${result.scan.scan.scan_type} scan`}
          />

          {result.scan.scan.summary && (
            <div className="callout callout-info">
              <ShieldCheck size={16} />
              <span>{result.scan.scan.summary}</span>
            </div>
          )}

          <div className="metric-grid">
            <MetricCard
              label="Files analyzed"
              value={result.scan.files_analyzed == null ? '—' : String(result.scan.files_analyzed)}
              icon={<FileCode2 size={17} />}
              detail="Files inspected"
            />
            <MetricCard
              label="Total findings"
              value={String(result.scan.findings.length)}
              icon={<ShieldAlert size={17} />}
              detail="Findings returned"
            />
            <MetricCard
              label="Semgrep findings"
              value={result.scan.semgrep_findings == null ? '—' : String(result.scan.semgrep_findings)}
              icon={<Activity size={17} />}
              detail="Static analyzer output"
            />
            <MetricCard
              label="Scan status"
              value={result.scan.scan.status}
              icon={<CheckCircle2 size={17} />}
              detail={result.scan.scan.commit_sha?.slice(0, 8) ?? 'Commit unavailable'}
            />
          </div>

          <div className="scan-result-findings">
            <PanelHeading
              title="Detected findings"
              subtitle="Findings returned by the completed assessment."
            />

            {result.scan.findings.length ? (
              result.scan.findings.map((finding) => (
                <div className="report-finding" key={finding.id}>
                  <div>
                    <SeverityPill severity={finding.severity} />
                    <StatusBadge>{formatStatus(finding.status)}</StatusBadge>
                  </div>
                  <strong>{finding.title}</strong>
                  <span>{finding.vulnerability_type}</span>
                  <span>
                    {finding.file_path || 'File not specified'}
                    {finding.line_number ? `:${finding.line_number}` : ''}
                  </span>
                  <p>{finding.description}</p>
                  {finding.evidence && (
                    <DetailSection title="Evidence" text={finding.evidence} />
                  )}
                  {finding.remediation && (
                    <p>
                      <strong>Remediation:</strong> {finding.remediation}
                    </p>
                  )}
                </div>
              ))
            ) : (
              <div className="empty-state">
                <CheckCircle2 size={20} />
                <strong>No findings returned</strong>
                <span>The scan did not return any security findings.</span>
              </div>
            )}
          </div>

          {result.scan.limitations == null ? (
            <div className="callout callout-warning">
              <TriangleAlert size={16} />
              <span>Scan limitations were not recorded for this assessment.</span>
            </div>
          ) : result.scan.limitations.length > 0 ? (
            <div className="callout callout-warning">
              <TriangleAlert size={16} />
              <div>
                <strong>Scan limitations</strong>
                {result.scan.limitations.map((item, index) => (
                  <p key={index}>{item}</p>
                ))}
              </div>
            </div>
          ) : (
            <div className="callout callout-info scan-no-limitations">
              <ShieldCheck size={16} />
              <span>No scan limitations were reported.</span>
            </div>
          )}
        </section>
      )}

      <section className="panel table-panel">
        <PanelHeading
          title="Scan history"
          subtitle="Previous security assessments from your connected repositories."
          action={
            <Button
              variant="secondary"
              onClick={() => void history.refetch()}
            >
              <RefreshCw size={14} /> Refresh
            </Button>
          }
        />

        {history.isLoading ? (
          <div className="empty-state">
            <LoaderCircle size={18} className="spin" />
            Loading scan history…
          </div>
        ) : history.isError ? (
          <div className="callout callout-warning">
            <TriangleAlert size={16} />
            {getApiErrorMessage(history.error)}
            <Button variant="secondary" onClick={() => void history.refetch()}>
              <RefreshCw size={14} /> Retry
            </Button>
          </div>
        ) : history.data?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>SCAN</th>
                  <th>TYPE</th>
                  <th>STATUS</th>
                  <th>COMMIT</th>
                  <th>CREATED</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((scan) => {
                  const repo = repos.data?.find(
                    (item) => item.id === scan.repository_id,
                  )

                  return (
                    <tr key={scan.id}>
                      <td>
                        <strong>{repo?.full_name ?? scan.repository_id}</strong>
                      </td>
                      <td>{scan.scan_type}</td>
                      <td>
                        <StatusBadge
                          tone={
                            scan.status === 'completed'
                              ? 'success'
                              : scan.status === 'failed'
                                ? 'danger'
                                : 'warning'
                          }
                        >
                          {formatStatus(scan.status)}
                        </StatusBadge>
                      </td>
                      <td>{scan.commit_sha?.slice(0, 8) ?? '—'}</td>
                      <td>{formatDate(scan.created_at)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <Activity size={20} />
            <strong>No scan history</strong>
            <span>Your completed scans will appear here.</span>
          </div>
        )}
      </section>
    </>
  )
}

function VulnerabilitiesPage() {
  const notify = useNotify()
  const queryClient = useQueryClient()
  const [searchText, setSearchText] = useState('')
  const [search, setSearch] = useState('')
  const [categoryText, setCategoryText] = useState('')
  const [category, setCategory] = useState('')
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [selectedFinding, setSelectedFinding] = useState<ScanFinding | null>(
    null,
  )
  const [offset, setOffset] = useState(0)
  const limit = 20
  const summaryMetric = (value: number | undefined) =>
    summary.isLoading ? '…' : summary.isError ? '—' : String(value ?? 0)

  useEffect(() => {
    const timer = window.setTimeout(() => setSearch(searchText.trim()), 300)
    return () => window.clearTimeout(timer)
  }, [searchText])

  useEffect(() => {
    const timer = window.setTimeout(
      () => setCategory(categoryText.trim()),
      300,
    )
    return () => window.clearTimeout(timer)
  }, [categoryText])

  const findings = useQuery({
    queryKey: ['findings', limit, offset, severity, status, search, category],
    queryFn: () =>
      vulnerabilityService.list({
        limit,
        offset,
        severity: severity || undefined,
        status: status || undefined,
        search: search || undefined,
        vulnerability_type: category || undefined,
      }),
  })

  const summary = useQuery({
    queryKey: ['finding-summary'],
    queryFn: vulnerabilityService.summary,
  })

  const update = useMutation({
    mutationFn: ({
      id,
      nextStatus,
    }: {
      id: string
      nextStatus: FindingStatus
    }) => vulnerabilityService.updateStatus(id, nextStatus),
    onSuccess: async () => {
      notify('Finding status updated.', 'success')
      setSelectedFinding(null)
      await findings.refetch()
      await Promise.all([
        summary.refetch(),
        queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard-trends'] }),
      ])
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })

  const openFinding = (finding: ScanFinding) => {
    setSelectedFinding(finding)
  }

  return (
    <>
      <PageHeading
        eyebrow="RISK MANAGEMENT"
        title="Vulnerabilities"
        description="Review security findings, investigate evidence and manage remediation status."
      />

      <section className="metric-grid">
        <MetricCard
          label="Total findings"
          value={summaryMetric(summary.data?.total)}
          icon={<ShieldAlert size={17} />}
          detail="Recorded findings"
        />
        <MetricCard
          label="Critical"
          value={summaryMetric(summary.data?.by_severity?.critical)}
          icon={<AlertTriangle size={17} />}
          detail="Critical severity"
          alert
        />
        <MetricCard
          label="High"
          value={summaryMetric(summary.data?.by_severity?.high)}
          icon={<Activity size={17} />}
          detail="High severity"
        />
        <MetricCard
          label="Open"
          value={summaryMetric(summary.data?.by_status?.open)}
          icon={<Clock3 size={17} />}
          detail="Awaiting remediation"
        />
      </section>

      {summary.isError && (
        <div className="callout callout-warning">
          <TriangleAlert size={16} />
          {getApiErrorMessage(summary.error)}
        </div>
      )}

      <section className="panel table-panel">
        <div className="table-toolbar">
          <div>
            <strong>Security findings</strong>
            <span> · {findings.data?.total ?? 0} matching records</span>
          </div>

          <div className="table-toolbar-actions">
            <div className="search-field">
              <Search size={15} />
              <input
                value={searchText}
                maxLength={100}
                onChange={(event) => {
                  setSearchText(event.target.value)
                  setOffset(0)
                }}
                placeholder="Search findings"
              />
            </div>

            <div className="search-field">
              <Search size={15} />
              <input
                value={categoryText}
                maxLength={100}
                aria-label="Filter by finding category"
                onChange={(event) => {
                  setCategoryText(event.target.value)
                  setOffset(0)
                }}
                placeholder="Filter by category"
              />
            </div>

            <select
              value={severity}
              onChange={(event) => {
                setSeverity(event.target.value)
                setOffset(0)
              }}
              aria-label="Filter by severity"
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>

            <select
              value={status}
              onChange={(event) => {
                setStatus(event.target.value)
                setOffset(0)
              }}
              aria-label="Filter by status"
            >
              <option value="">All statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In progress</option>
              <option value="resolved">Resolved</option>
              <option value="ignored">Ignored</option>
              <option value="false_positive">False positive</option>
            </select>
          </div>
        </div>

        {findings.isLoading ? (
          <div className="empty-state">
            <LoaderCircle size={20} className="spin" />
            Loading findings…
          </div>
        ) : findings.isError ? (
          <div className="callout callout-warning">
            <TriangleAlert size={16} />
            {getApiErrorMessage(findings.error)}
          </div>
        ) : findings.data?.items.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>FINDING</th>
                  <th>SEVERITY</th>
                  <th>TYPE</th>
                  <th>LOCATION</th>
                  <th>STATUS</th>
                  <th>CREATED</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {findings.data.items.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <button
                        className="finding-title-button"
                        onClick={() => openFinding(finding)}
                      >
                        {finding.title}
                      </button>
                    </td>
                    <td>
                      <SeverityPill severity={finding.severity} />
                    </td>
                    <td>{finding.vulnerability_type}</td>
                    <td>
                      {finding.file_path || '—'}
                      {finding.line_number ? `:${finding.line_number}` : ''}
                    </td>
                    <td>
                      <StatusBadge
                        tone={
                          finding.status === 'resolved'
                            ? 'success'
                            : finding.status === 'open'
                              ? 'danger'
                              : 'warning'
                        }
                      >
                        {formatStatus(finding.status)}
                      </StatusBadge>
                    </td>
                    <td>{formatDate(finding.created_at)}</td>
                    <td>
                      <Button
                        variant="quiet"
                        onClick={() => openFinding(finding)}
                      >
                        Details <ArrowRight size={13} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <CheckCircle2 size={20} />
            <strong>No findings found</strong>
            <span>Try changing the filters or run a security scan.</span>
          </div>
        )}

        <div className="pagination-row">
          <span>
            Showing {findings.data?.items.length ?? 0} of{' '}
            {findings.data?.total ?? 0}
          </span>

          <div>
            <Button
              variant="secondary"
              disabled={offset === 0}
              onClick={() => setOffset(Math.max(0, offset - limit))}
            >
              Previous
            </Button>
            <Button
              variant="secondary"
              disabled={
                !findings.data ||
                offset + limit >= findings.data.total
              }
              onClick={() => setOffset(offset + limit)}
            >
              Next
            </Button>
          </div>
        </div>
      </section>

      {selectedFinding && (
        <Modal
          title="Finding details"
          onClose={() => setSelectedFinding(null)}
          wide
        >
          <FindingDetails
            finding={selectedFinding}
            pending={update.isPending}
            onStatusChange={(nextStatus) =>
              update.mutate({
                id: selectedFinding.id,
                nextStatus,
              })
            }
          />
        </Modal>
      )}
    </>
  )
}

function FindingDetails({
  finding,
  onStatusChange,
  pending,
}: {
  finding: ScanFinding
  onStatusChange: (status: FindingStatus) => void
  pending: boolean
}) {
  return (
    <div className="finding-details">
      <div className="finding-detail-heading">
        <SeverityPill severity={finding.severity} />
        <StatusBadge>{formatStatus(finding.status)}</StatusBadge>
      </div>

      <h3>{finding.title}</h3>
      <p>{finding.description || 'No description provided.'}</p>

      <div className="detail-grid">
        <Detail label="Finding type" value={finding.vulnerability_type} />
        <Detail label="File" value={finding.file_path || 'Not specified'} />
        <Detail
          label="Line"
          value={finding.line_number ? String(finding.line_number) : 'Not specified'}
        />
        <Detail label="Scan ID" value={finding.scan_id} />
        <Detail label="Created" value={formatDate(finding.created_at)} />
      </div>

      {finding.evidence && (
        <DetailSection title="Evidence" text={finding.evidence} />
      )}

      {finding.remediation && (
        <DetailSection title="Remediation" text={finding.remediation} />
      )}

      <div className="form-field">
        <label className="field-label" htmlFor="finding-status">
          Update status
        </label>

        <select
          id="finding-status"
          value={finding.status}
          disabled={pending}
          onChange={(event) =>
            onStatusChange(event.target.value as FindingStatus)
          }
        >
          <option value="open">Open</option>
          <option value="in_progress">In progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False positive</option>
        </select>
      </div>
    </div>
  )
}

function DetailSection({
  title,
  text,
}: {
  title: string
  text: string
}) {
  return (
    <section className="detail-section">
      <h4>{title}</h4>
      <pre>{text}</pre>
    </section>
  )
}
function ReportsPage() {
  const repos = useQuery({
    queryKey: ['connected-repositories'],
    queryFn: repositoryService.listConnected,
    enabled: Boolean(authService.getAccessToken()),
  })

  const scans = useQuery({
    queryKey: ['scan-history'],
    queryFn: scanService.list,
    enabled: Boolean(authService.getAccessToken()),
  })

  const notify = useNotify()

  const createDownload = useMutation({
    mutationFn: async (scanId: string) => {
      const scan = scans.data?.find((item) => item.id === scanId)
      if (!scan) throw new Error('The selected scan is no longer available.')

      return reportService.getRepositoryReport(scan.repository_id, scan.id)
    },
    onSuccess: (report) => {
      downloadReport(report)
      notify('Security report generated.', 'success')
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })

  return (
    <>
      <PageHeading
        eyebrow="ASSESSMENT OUTPUT"
        title="Reports"
        description="Generate downloadable security reports from your recorded scan results."
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              void scans.refetch()
              void repos.refetch()
            }}
          >
            <RefreshCw size={14} /> Refresh
          </Button>
        }
      />

      <section className="panel table-panel">
        <PanelHeading
          title="Available scan reports"
          subtitle="Each report contains the scan details and findings recorded for that assessment."
        />

        {scans.isLoading || repos.isLoading ? (
          <div className="empty-state">
            <LoaderCircle size={20} className="spin" />
            Loading report data…
          </div>
        ) : scans.isError || repos.isError ? (
          <div className="callout callout-warning">
            <TriangleAlert size={16} />
            {getApiErrorMessage(scans.error ?? repos.error)}
          </div>
        ) : scans.data?.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>REPOSITORY</th>
                  <th>SCAN TYPE</th>
                  <th>STATUS</th>
                  <th>CREATED</th>
                  <th>REPORT</th>
                </tr>
              </thead>

              <tbody>
                {scans.data.map((scan) => {
                  const repo = repos.data?.find(
                    (item) => item.id === scan.repository_id,
                  )

                  return (
                    <tr key={scan.id}>
                      <td>
                        <strong>
                          {repo?.full_name ?? scan.repository_id}
                        </strong>
                      </td>
                      <td>{scan.scan_type}</td>
                      <td>
                        <StatusBadge
                          tone={
                            scan.status === 'completed'
                              ? 'success'
                              : scan.status === 'failed'
                                ? 'danger'
                                : 'warning'
                          }
                        >
                          {formatStatus(scan.status)}
                        </StatusBadge>
                      </td>
                      <td>{formatDate(scan.created_at)}</td>
                      <td>
                        <Button
                          variant="secondary"
                          disabled={
                            scan.status !== 'completed' ||
                            createDownload.isPending
                          }
                          onClick={() => createDownload.mutate(scan.id)}
                        >
                          {createDownload.isPending ? (
                            <LoaderCircle size={14} className="spin" />
                          ) : (
                            <FileText size={14} />
                          )}
                          Download
                        </Button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <FileText size={20} />
            <strong>No reports available</strong>
            <span>Run a security scan to generate your first report.</span>
          </div>
        )}
      </section>
    </>
  )
}

function PullRequestsPage() {
  const notify = useNotify()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<{
    repo: ConnectedRepository
    request: PullRequest
  } | null>(null)
  const [review, setReview] = useState<PullRequestReview | null>(null)

  const repos = useQuery({
    queryKey: ['connected-repositories'],
    queryFn: repositoryService.listConnected,
    enabled: Boolean(authService.getAccessToken()),
  })

  const pullRequests = useQuery({
    queryKey: ['repository-pull-requests', repos.data?.map((repo) => repo.id)],
    queryFn: async () => {
      const repositories = repos.data ?? []
      const results: { repo: ConnectedRepository; request: PullRequest }[] = []

      for (let index = 0; index < repositories.length; index += 3) {
        const batch = repositories.slice(index, index + 3)
        const batchResults = await Promise.all(
          batch.map(async (repo) => {
            const requests = await pullRequestService.list(repo.id)
            return requests.map((request) => ({ repo, request }))
          }),
        )
        results.push(...batchResults.flat())
      }

      return results
    },
    enabled: Boolean(repos.data?.length),
  })

  const runReview = useMutation({
    mutationFn: () => {
      if (!selected) throw new Error('Select a pull request first.')
      return pullRequestService.review(
        selected.repo.id,
        selected.request.number,
      )
    },
    onSuccess: async (data) => {
      setReview(data)
      notify(
        data.status === 'completed'
          ? 'Pull request security review completed.'
          : `Pull request review status: ${formatStatus(data.status)}.`,
        data.status === 'completed' ? 'success' : 'info',
      )
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['scan-history'] }),
        queryClient.invalidateQueries({ queryKey: ['findings'] }),
        queryClient.invalidateQueries({ queryKey: ['finding-summary'] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard-overview'] }),
        queryClient.invalidateQueries({ queryKey: ['dashboard-trends'] }),
      ])
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })

  return (
    <>
      <PageHeading
        eyebrow="PULL REQUEST SECURITY"
        title="Pull requests"
        description="Review open pull requests from your connected repositories with RepLock's security analysis."
        actions={
          <Button
            variant="secondary"
            onClick={() => void pullRequests.refetch()}
          >
            <RefreshCw size={14} /> Refresh
          </Button>
        }
      />

      {repos.isLoading || pullRequests.isLoading ? (
        <div className="panel empty-state">
          <LoaderCircle size={20} className="spin" />
          <strong>Loading pull requests</strong>
          <span>Fetching pull requests from connected repositories…</span>
        </div>
      ) : repos.isError || pullRequests.isError ? (
        <div className="callout callout-warning">
          <TriangleAlert size={16} />
          {getApiErrorMessage(repos.error ?? pullRequests.error)}
          <Button
            variant="secondary"
            onClick={() => {
              void repos.refetch()
              void pullRequests.refetch()
            }}
          >
            <RefreshCw size={14} /> Retry
          </Button>
        </div>
      ) : !repos.data?.length ? (
        <div className="panel empty-state">
          <GitPullRequest size={22} />
          <strong>No connected repositories</strong>
          <span>Connect a GitHub repository to review its pull requests.</span>
          <Link className="button button-primary" to="/repositories">
            Connect repository
          </Link>
        </div>
      ) : pullRequests.data?.length ? (
        <section className="panel table-panel">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>PULL REQUEST</th>
                  <th>REPOSITORY</th>
                  <th>AUTHOR</th>
                  <th>BASE BRANCH</th>
                  <th>FILES</th>
                  <th>CHANGES</th>
                  <th />
                </tr>
              </thead>

              <tbody>
                {pullRequests.data.map(({ repo, request }) => (
                  <tr key={`${repo.id}-${request.number}`}>
                    <td>
                      <a
                        className="finding-title-button"
                        href={request.html_url}
                        target="_blank"
                        rel="noreferrer"
                      >
                        #{request.number} {request.title}
                      </a>
                    </td>
                    <td>{repo.full_name}</td>
                    <td>{request.author || 'Unknown'}</td>
                    <td>{request.base_branch}</td>
                    <td>{request.changed_files}</td>
                    <td>
                      <span className="change-additions">
                        +{request.additions}
                      </span>{' '}
                      <span className="change-deletions">
                        -{request.deletions}
                      </span>
                    </td>
                    <td>
                      <Button
                        variant="secondary"
                        onClick={() => {
                          setSelected({ repo, request })
                          setReview(null)
                        }}
                      >
                        Review <ArrowRight size={13} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : (
        <section className="panel empty-state">
          <GitPullRequest size={22} />
          <strong>No pull requests found</strong>
          <span>
            No pull requests were returned for your connected repositories.
          </span>
        </section>
      )}

      {selected && (
        <Modal
          title={`Review pull request #${selected.request.number}`}
          onClose={() => {
            setSelected(null)
            setReview(null)
          }}
          wide
        >
          <div className="pr-review-header">
            <div>
              <strong>{selected.request.title}</strong>
              <span>{selected.repo.full_name}</span>
            </div>
            <a
              href={selected.request.html_url}
              target="_blank"
              rel="noreferrer"
              className="text-link"
            >
              Open on GitHub <ArrowRight size={13} />
            </a>
          </div>

          <div className="detail-grid">
            <Detail
              label="Author"
              value={selected.request.author || 'Unknown'}
            />
            <Detail
              label="Base branch"
              value={selected.request.base_branch}
            />
            <Detail
              label="Changed files"
              value={String(selected.request.changed_files)}
            />
            <Detail
              label="Head commit"
              value={selected.request.head_sha.slice(0, 8)}
            />
          </div>

          <Button
            disabled={runReview.isPending}
            onClick={() => runReview.mutate()}
          >
            {runReview.isPending ? (
              <LoaderCircle size={15} className="spin" />
            ) : (
              <ShieldCheck size={15} />
            )}
            {runReview.isPending
              ? 'Running security review…'
              : 'Run security review'}
          </Button>

          {review && (
            <div className="pr-review-results">
              <div className="callout callout-info">
                <CheckCircle2 size={16} />
                <div>
                  <strong>Review {formatStatus(review.status)}</strong>
                  <p>{review.summary}</p>
                  <p>Changed files: {review.changed_files}</p>
                  <p>Files analyzed: {review.files_analyzed}</p>
                  <p>Reviewed head commit: {review.head_sha}</p>
                  <p>Scan ID: {review.scan_id}</p>
                </div>
              </div>
              {review.head_sha !== selected.request.head_sha && (
                <div className="callout callout-warning">
                  <TriangleAlert size={16} />
                  <span>
                    The pull request head changed after it was listed. This
                    review is for {review.head_sha.slice(0, 8)}, not the
                    previously listed {selected.request.head_sha.slice(0, 8)}.
                  </span>
                </div>
              )}

              <PanelHeading
                title="Review findings"
                subtitle={`${review.findings.length} findings returned by the review`}
              />

              {review.findings.length ? (
                review.findings.map((finding) => (
                  <div className="report-finding" key={finding.id}>
                    <div>
                      <SeverityPill severity={finding.severity} />
                      <StatusBadge>{formatStatus(finding.status)}</StatusBadge>
                    </div>
                    <strong>{finding.title}</strong>
                    <span>
                      {finding.file_path || 'File not specified'}
                      {finding.line_number ? `:${finding.line_number}` : ''}
                    </span>
                    <p>{finding.description}</p>
                    {finding.evidence && (
                      <DetailSection
                        title="Evidence"
                        text={finding.evidence}
                      />
                    )}
                    {finding.remediation && (
                      <DetailSection
                        title="Remediation"
                        text={finding.remediation}
                      />
                    )}
                  </div>
                ))
              ) : (
                <div className="empty-state">
                  <CheckCircle2 size={18} />
                  <strong>No findings returned</strong>
                  <span>The review did not return security findings.</span>
                </div>
              )}

              {review.limitations.length > 0 && (
                <div className="callout callout-warning">
                  <TriangleAlert size={16} />
                  <div>
                    <strong>Review limitations</strong>
                    {review.limitations.map((item, index) => (
                      <p key={index}>{item}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </Modal>
      )}
    </>
  )
}

function MergeIntelligencePage() {
  const notify = useNotify()
  const [repository, setRepository] = useState('')
  const [branchA, setBranchA] = useState('')
  const [branchB, setBranchB] = useState('')
  const [analysis, setAnalysis] = useState<MergeAnalysis | null>(null)

  const repos = useQuery({
    queryKey: ['connected-repositories'],
    queryFn: repositoryService.listConnected,
    enabled: Boolean(authService.getAccessToken()),
  })

  const analyze = useMutation({
    mutationFn: () =>
      mergeIntelligenceService.analyze(
        repository,
        branchA.trim(),
        branchB.trim(),
      ),
    onSuccess: (data) => {
      setAnalysis(data)
      notify('Branch analysis completed.', 'success')
    },
    onError: (error) => notify(getApiErrorMessage(error), 'error'),
  })

  return (
    <>
      <PageHeading
        eyebrow="BRANCH SECURITY ANALYSIS"
        title="Merge intelligence"
        description="Compare two branches and inspect security findings in the changed code."
      />

      {repos.isLoading ? (
        <div className="panel empty-state">
          <LoaderCircle size={19} className="spin" />
          Loading connected repositories…
        </div>
      ) : repos.isError ? (
        <div className="callout callout-warning">
          <TriangleAlert size={16} />
          {getApiErrorMessage(repos.error)}
          <Button variant="secondary" onClick={() => void repos.refetch()}>
            <RefreshCw size={14} /> Retry
          </Button>
        </div>
      ) : !repos.data?.length ? (
        <div className="panel empty-state">
          <GitMerge size={22} />
          <strong>No connected repositories</strong>
          <span>Connect a repository before analyzing branches.</span>
          <Link className="button button-primary" to="/repositories">
            Connect repository
          </Link>
        </div>
      ) : (
        <>
          <section className="panel merge-config">
            <div className="merge-select">
              <label className="field-label" htmlFor="merge-repo">
                Repository
              </label>
              <div className="select-wrap">
                <select
                  id="merge-repo"
                  value={repository}
                  onChange={(event) => {
                    const repo = repos.data?.find(
                      (item) => item.id === event.target.value,
                    )
                    setRepository(event.target.value)
                    setBranchA(repo?.default_branch || 'main')
                    setAnalysis(null)
                  }}
                >
                  <option value="">Select repository</option>
                  {repos.data.map((repo) => (
                    <option key={repo.id} value={repo.id}>
                      {repo.full_name}
                    </option>
                  ))}
                </select>
                <ChevronDown size={14} />
              </div>
            </div>

            <div className="merge-select">
              <label className="field-label" htmlFor="branch-a">
                Base branch
              </label>
              <div className="input-with-icon">
                <GitBranch size={14} />
                <input
                  id="branch-a"
                  value={branchA}
                  onChange={(event) => setBranchA(event.target.value)}
                  placeholder="main"
                />
              </div>
            </div>

            <div className="merge-connector">
              <GitMerge size={16} />
            </div>

            <div className="merge-select">
              <label className="field-label" htmlFor="branch-b">
                Compare branch
              </label>
              <div className="input-with-icon">
                <GitBranch size={14} />
                <input
                  id="branch-b"
                  value={branchB}
                  onChange={(event) => setBranchB(event.target.value)}
                  placeholder="feature-branch"
                />
              </div>
            </div>

            <Button
              disabled={
                !repository ||
                !branchA.trim() ||
                !branchB.trim() ||
                branchA.trim() === branchB.trim() ||
                analyze.isPending
              }
              onClick={() => {
                setAnalysis(null)
                analyze.mutate()
              }}
            >
              {analyze.isPending ? (
                <LoaderCircle size={15} className="spin" />
              ) : (
                <Sparkles size={15} />
              )}
              Analyze branches
            </Button>
          </section>

          {analysis && (
            <>
              <div className="merge-summary-banner">
                <div className="merge-summary-icon">
                  <GitMerge size={18} />
                </div>
                <div>
                  <span className="eyebrow">
                    BACKEND COMPARISON · {analysis.comparison_status}
                  </span>
                  <h2>{analysis.summary}</h2>
                  <p>
                    {analysis.repository} · {analysis.branch_a} compared with{' '}
                    {analysis.branch_b}
                  </p>
                </div>
                <StatusBadge
                  tone={analysis.findings.length ? 'warning' : 'success'}
                >
                  {analysis.findings.length} findings
                </StatusBadge>
              </div>

              <section className="metric-grid">
                <MetricCard
                  label="Changed files"
                  value={String(analysis.changed_files)}
                  icon={<FileCode2 size={17} />}
                  detail="Reported by branch comparison"
                />
                <MetricCard
                  label="Files analyzed"
                  value={String(analysis.files_analyzed)}
                  icon={<Activity size={17} />}
                  detail="Analyzed by security engine"
                />
                <MetricCard
                  label="Commits ahead"
                  value={String(analysis.ahead_by)}
                  icon={<ArrowUpRight size={17} />}
                  detail="Compare branch ahead"
                />
                <MetricCard
                  label="Commits behind"
                  value={String(analysis.behind_by)}
                  icon={<ArrowDownRight size={17} />}
                  detail="Compare branch behind"
                />
              </section>

              <section className="panel">
                <PanelHeading
                  title="Logical merge conflicts"
                  subtitle="Semantic incompatibilities identified across the branch changes"
                />

                {analysis.conflicts.length ? (
                  analysis.conflicts.map((conflict, index) => (
                    <div
                      className="report-finding"
                      key={`${conflict.conflict_type}-${index}`}
                    >
                      <div>
                        <StatusBadge
                          tone={
                            conflict.status === 'confirmed'
                              ? 'danger'
                              : 'warning'
                          }
                        >
                          {formatStatus(conflict.status)}
                        </StatusBadge>
                        <StatusBadge>
                          {Math.round(conflict.confidence * 100)}% confidence
                        </StatusBadge>
                      </div>
                      <strong>{conflict.conflict_type}</strong>
                      <p>{conflict.explanation}</p>
                      <DetailSection
                        title="Affected files"
                        text={conflict.affected_files.join('\n')}
                      />
                      {conflict.related_symbols.length > 0 && (
                        <DetailSection
                          title="Related symbols"
                          text={conflict.related_symbols.join('\n')}
                        />
                      )}
                      {conflict.dependency_description && (
                        <DetailSection
                          title="Dependency"
                          text={conflict.dependency_description}
                        />
                      )}
                      {conflict.evidence.map((evidence, evidenceIndex) => (
                        <DetailSection
                          key={`${evidence.branch}-${evidence.file_path}-${evidenceIndex}`}
                          title={`${evidence.branch} · ${evidence.file_path}:${evidence.line_start}-${evidence.line_end}`}
                          text={evidence.code}
                        />
                      ))}
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <CheckCircle2 size={19} />
                    <strong>No logical conflicts identified</strong>
                    <span>
                      No semantic incompatibilities were returned for these
                      branch changes.
                    </span>
                  </div>
                )}
              </section>

              <section className="panel">
                <PanelHeading
                  title="Security findings"
                  subtitle="Findings returned by merge intelligence"
                />

                {analysis.findings.length ? (
                  analysis.findings.map((finding) => (
                    <div
                      className="report-finding"
                      key={`${finding.file_path}-${finding.line_start}-${finding.title}`}
                    >
                      <div>
                        <SeverityPill severity={finding.severity} />
                        <StatusBadge>
                          {Math.round(finding.confidence * 100)}% confidence
                        </StatusBadge>
                      </div>
                      <strong>{finding.title}</strong>
                      <span>
                        {finding.file_path}:{finding.line_start}
                        {finding.line_end !== finding.line_start
                          ? `-${finding.line_end}`
                          : ''}
                      </span>
                      <p>{finding.description}</p>
                      <DetailSection title="Evidence" text={finding.evidence} />
                      <DetailSection
                        title="Remediation"
                        text={finding.remediation}
                      />
                      {finding.references.length > 0 && (
                        <div className="finding-references">
                          {finding.references.map((reference) => (
                            <a
                              key={reference.url}
                              href={reference.url}
                              target="_blank"
                              rel="noreferrer"
                              className="text-link"
                            >
                              {reference.title} <ArrowRight size={13} />
                            </a>
                          ))}
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <CheckCircle2 size={19} />
                    <strong>No findings returned</strong>
                    <span>
                      The analysis did not return security findings for this
                      comparison.
                    </span>
                  </div>
                )}
              </section>

              {analysis.limitations.length > 0 && (
                <div className="callout callout-warning">
                  <TriangleAlert size={16} />
                  <div>
                    <strong>Analysis limitations</strong>
                    {analysis.limitations.map((item, index) => (
                      <p key={index}>{item}</p>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </>
      )}
    </>
  )
}

function SettingsPage() {
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const health = useQuery({
    queryKey: ['settings-api-health'],
    queryFn: async () =>
      (await healthApi.get<{ status: string }>('/health')).data,
    retry: false,
  })

  const account = useQuery({
    queryKey: ['current-user'],
    queryFn: authService.getCurrentUser,
    enabled: Boolean(authService.getAccessToken()),
    retry: false,
  })

  return (
    <>
      <PageHeading
        eyebrow="WORKSPACE PREFERENCES"
        title="Settings"
        description="Integration status and workspace configuration."
        actions={
          <Button
            variant="secondary"
            onClick={() => {
              authService.clearAccessToken()
              queryClient.clear()
              navigate('/login', { replace: true })
            }}
          >
            <LockKeyhole size={15} /> Sign out
          </Button>
        }
      />

      <section className="panel settings-panel">
        <PanelHeading
          title="Backend connection"
          subtitle="RepLock API endpoint and service availability"
        />

        <div className="settings-row">
          <div className="settings-icon">
            <Server size={17} />
          </div>
          <div>
            <strong>API base URL</strong>
            <span>
              Configured using the VITE_API_URL environment variable.
            </span>
          </div>
          <code>
            {import.meta.env.VITE_API_URL || 'http://localhost:8000'}
          </code>
        </div>

        <div className="settings-row">
          <div className="settings-icon">
            <Activity size={17} />
          </div>
          <div>
            <strong>Backend health</strong>
            <span>
              {health.isSuccess
                ? 'Health endpoint responded successfully.'
                : health.isLoading
                  ? 'Checking backend availability…'
                  : 'Unable to reach the health endpoint.'}
            </span>
          </div>
          <StatusBadge
            tone={
              health.isSuccess
                ? 'success'
                : health.isLoading
                  ? 'neutral'
                  : 'danger'
            }
          >
            {health.isSuccess
              ? 'Connected'
              : health.isLoading
                ? 'Checking'
                : 'Offline'}
          </StatusBadge>
        </div>

        <div className="settings-row">
          <div className="settings-icon">
            <GithubMark size={17} />
          </div>
          <div>
            <strong>GitHub OAuth</strong>
            <span>
              {account.isSuccess
                ? `Signed in as ${account.data.username} · ${account.data.email ?? 'No verified email returned by GitHub'}.`
                : account.isLoading
                  ? 'Checking the current GitHub session…'
                  : 'Sign in with GitHub to connect your repositories.'}
            </span>
          </div>
          <Link
            className="text-link"
            to={account.isSuccess ? '/repositories' : '/login'}
          >
            {account.isSuccess ? 'View repositories' : 'Connect GitHub'}
            <ArrowRight size={14} />
          </Link>
        </div>
      </section>

      <div className="settings-note">
        <ShieldEllipsis size={16} />
        <span>
          Workspace preferences and backend connectivity are available here.
        </span>
      </div>
    </>
  )
}

function LoginPage() {
  const [errorMessage, setErrorMessage] = useState('')

  const beginLogin = () => {
    setErrorMessage('')
    authService.beginGithubOAuth()
  }

  return (
    <div className="login-page">
      <header className="login-topbar">
        <Link to="/" className="brand-link">
          <Brand />
        </Link>

        <Link to="/" className="login-back">
          <ArrowRight size={14} /> Back to workspace
        </Link>
      </header>

      <main className="login-content">
        <div className="login-card">
          <div className="login-logo">
            <Brand compact />
          </div>

          <div className="eyebrow">
            SECURE EVERY COMMIT. PROTECT EVERY MERGE.
          </div>

          <h1>
            Security that ships
            <br />
            with your code.
          </h1>

          <p className="login-description">
            RepLock maps your repository’s attack surface, runs authorized
            security tests, validates findings and gives your team clear,
            evidence-backed fixes.
          </p>

          <div className="login-benefits">
            <div>
              <span>
                <ShieldCheck size={15} />
              </span>
              <p>
                <strong>Repository security scans</strong>
                <small>
                    Run backend-powered assessments on connected repositories.
                </small>
              </p>
            </div>

            <div>
              <span>
                <BookOpenCheck size={15} />
              </span>
              <p>
                <strong>Evidence-backed findings</strong>
                <small>
                  Understand impact, validation and remediation.
                </small>
              </p>
            </div>

            <div>
              <span>
                <GitMerge size={15} />
              </span>
              <p>
                <strong>Safer merges</strong>
                <small>
                  Catch security and semantic conflicts early.
                </small>
              </p>
            </div>
          </div>

          <Button
            className="github-login-button"
            onClick={beginLogin}
          >
            <GithubMark size={17} />
            Continue with GitHub
            <ArrowRight size={15} />
          </Button>

          {errorMessage && (
            <div className="login-error" role="alert">
              <TriangleAlert size={15} />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="login-privacy">
            <LockKeyhole size={13} />
            Read-only until you explicitly authorize a security assessment.
          </div>
        </div>

        <div className="login-side-art">
          <div className="login-art-orbit" />
          <div className="login-art-orbit orbit-two" />
          <div className="login-art-core">
            <Shield size={43} />
            <span />
          </div>

          <div className="art-data art-data-one">
            <span className="art-data-dot" />
            ATTACK SURFACE MAPPED
            <Check size={13} />
          </div>

          <div className="art-data art-data-two">
            <span className="art-data-dot red" />
            VULNERABILITY VALIDATED
            <AlertTriangle size={13} />
          </div>

          <div className="art-data art-data-three">
            <span className="art-data-dot green" />
            EVIDENCE COLLECTED
            <Check size={13} />
          </div>

          <div className="login-art-caption">
            <span>SECURITY, WITH CONTEXT</span>
            <p>Every finding, grounded in your code.</p>
          </div>
        </div>
      </main>

      <footer className="login-footer">
        <span>REPLOCK © 2026</span>
        <span>Secure every commit. Protect every merge.</span>
        <span>
          <Globe2 size={13} /> Built for engineering teams
        </span>
      </footer>
    </div>
  )
}

function NotFoundPage() {
  return (
    <div className="not-found">
      <Shield size={25} />
      <h1>Page not found</h1>
      <p>The page you’re looking for doesn’t exist.</p>
      <Link className="button button-primary" to="/">
        Return to overview
      </Link>
    </div>
  )
}

function App() {
  return (
    <NotificationProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/auth/callback" element={<AuthCallbackPage />} />

          <Route element={<RequireAuth />}>
            <Route element={<AppLayout />}>
              <Route index element={<OverviewPage />} />
              <Route path="repositories" element={<RepositoriesPage />} />
              <Route path="scans" element={<ScanningPage />} />
              <Route
                path="vulnerabilities"
                element={<VulnerabilitiesPage />}
              />
              <Route
                path="pull-requests"
                element={<PullRequestsPage />}
              />
              <Route
                path="merge-intelligence"
                element={<MergeIntelligencePage />}
              />
              <Route path="reports" element={<ReportsPage />} />
              <Route path="settings" element={<SettingsPage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
    </NotificationProvider>
  )
}

export default App