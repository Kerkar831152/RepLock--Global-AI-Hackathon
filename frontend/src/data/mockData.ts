import type { Repository, SecurityScan, Severity, Vulnerability } from '../types'
import type { PullRequest } from '../services/pullRequests'
import type { SecurityReport } from '../services/reports'

export const severityColors: Record<Severity, string> = {
  Critical: '#ff5b67',
  High: '#ff9e54',
  Medium: '#eac45c',
  Low: '#67a98e',
}

export const severityDistribution: Array<{ name: Severity; value: number; color: string }> = [
  { name: 'Critical', value: 2, color: severityColors.Critical },
  { name: 'High', value: 5, color: severityColors.High },
  { name: 'Medium', value: 8, color: severityColors.Medium },
  { name: 'Low', value: 4, color: severityColors.Low },
]

export const repositories: Repository[] = [
  { id: 'acme/payments-api', name: 'payments-api', owner: 'acme', language: 'TypeScript', branch: 'main', lastScan: '12 min ago', findings: 3, status: 'At risk' },
  { id: 'acme/customer-portal', name: 'customer-portal', owner: 'acme', language: 'Python', branch: 'main', lastScan: 'Yesterday', findings: 1, status: 'Needs attention' },
  { id: 'acme/infrastructure', name: 'infrastructure', owner: 'acme', language: 'Terraform', branch: 'production', lastScan: '2 days ago', findings: 0, status: 'Secure' },
  { id: 'acme/auth-service', name: 'auth-service', owner: 'acme', language: 'Go', branch: 'main', lastScan: '5 days ago', findings: 2, status: 'Needs attention' },
]

export const scans: SecurityScan[] = [
  { id: 'scan-1042', repository: 'payments-api', branch: 'main', commit: 'a91f4d2', status: 'Completed', startedAt: 'Today, 10:42 AM', duration: '8m 24s', findings: 3, critical: 1 },
  { id: 'scan-1038', repository: 'customer-portal', branch: 'main', commit: '3bc80e1', status: 'Completed', startedAt: 'Yesterday, 4:18 PM', duration: '6m 02s', findings: 1, critical: 0 },
  { id: 'scan-1021', repository: 'infrastructure', branch: 'production', commit: '8f20a6c', status: 'Completed', startedAt: 'Oct 28, 9:05 AM', duration: '4m 51s', findings: 0, critical: 0 },
  { id: 'scan-1014', repository: 'auth-service', branch: 'main', commit: '51dd2ab', status: 'Completed', startedAt: 'Oct 26, 2:30 PM', duration: '7m 16s', findings: 2, critical: 0 },
]

export const vulnerabilities: Vulnerability[] = [
  {
    id: 'VUL-241', title: 'SQL injection in search endpoint', severity: 'Critical', repository: 'payments-api',
    file: 'src/routes/search.ts', line: 84, source: 'Dynamic testing', validation: 'Confirmed', remediation: 'Open',
    description: 'The search route interpolates a user-controlled query directly into a SQL statement.',
    impact: 'An unauthenticated attacker could read or modify records outside the intended search scope.',
    evidence: 'A controlled quote-based test altered the query result set and returned records outside the requested account.',
    reproduction: 'Send a search request with a quote and boolean condition in the query parameter. No destructive payloads were used.',
    explanation: 'The query builder receives raw input instead of a bound parameter, allowing user input to change query structure.',
    fix: 'Use parameterized queries or the ORM query builder. Add a regression test for quote and boolean characters.',
    snippet: 'const query = `SELECT * FROM invoices WHERE name LIKE \'%${search}%\'`',
  },
  {
    id: 'VUL-238', title: 'Missing authorization on invoice export', severity: 'High', repository: 'payments-api',
    file: 'src/controllers/export.ts', line: 42, source: 'Access control analysis', validation: 'Confirmed', remediation: 'In progress',
    description: 'Invoice export checks the session but does not verify ownership of the requested account.',
    impact: 'A signed-in user may export another organization’s invoices by changing the account identifier.',
    evidence: 'A read-only authorization test using two test accounts returned the second account’s export metadata.',
    reproduction: 'Request an export for an account outside the authenticated user’s membership. Testing used seeded test accounts.',
    explanation: 'Authentication establishes identity, but the handler does not enforce an account-level authorization check.',
    fix: 'Authorize account membership before generating the export and add cross-tenant access tests.',
    snippet: 'const accountId = req.params.accountId\n+ const exportData = await exportInvoices(accountId)',
  },
  {
    id: 'VUL-235', title: 'Potentially exposed debug endpoint', severity: 'Medium', repository: 'customer-portal',
    file: 'app/debug/routes.py', line: 19, source: 'Code analysis', validation: 'Suspected', remediation: 'Open',
    description: 'A debug route appears to be registered without an environment guard.',
    impact: 'If deployed, the endpoint may disclose internal application diagnostics.',
    evidence: 'Route registration is unconditional in the current code path. Runtime reachability has not been validated.',
    reproduction: 'Not validated. Confirm reachability only in an authorized staging environment.',
    explanation: 'Static analysis identified a debug route, but the deployment configuration may prevent exposure.',
    fix: 'Remove the route from production builds or require an explicit development-only configuration guard.',
    snippet: '@app.get("/debug/routes")\ndef list_routes():\n    return app.routes',
  },
  {
    id: 'VUL-229', title: 'Weak TLS configuration', severity: 'Low', repository: 'auth-service',
    file: 'deploy/ingress.yaml', line: 56, source: 'Configuration analysis', validation: 'Confirmed', remediation: 'Resolved',
    description: 'The ingress configuration allowed a legacy TLS protocol before the latest remediation.',
    impact: 'Legacy protocol support can weaken transport security for clients that negotiate older versions.',
    evidence: 'Configuration scan on commit 51dd2ab identified the legacy protocol setting.',
    reproduction: 'Static configuration check; no live endpoint probing was performed.',
    explanation: 'The configuration included an outdated protocol option that is no longer present in the current branch.',
    fix: 'Keep TLS 1.2 and 1.3 enabled and remove legacy protocol versions.',
    snippet: 'ssl_protocols: TLSv1.2 TLSv1.3',
  },
]

export const reports: SecurityReport[] = [
  { id: 'RPT-1042', repository: 'payments-api', commit: 'a91f4d2', date: 'Today, 10:50 AM', findings: 3, critical: 1, status: 'Complete' },
  { id: 'RPT-1038', repository: 'customer-portal', commit: '3bc80e1', date: 'Yesterday', findings: 1, critical: 0, status: 'Complete' },
  { id: 'RPT-1021', repository: 'infrastructure', commit: '8f20a6c', date: 'Oct 28, 9:10 AM', findings: 0, critical: 0, status: 'Complete' },
]

export const pullRequests: PullRequest[] = [
  { id: 'pr-284', number: 284, title: 'Add invoice search filters', repository: 'payments-api', author: 'maya-chen', source: 'feat/invoice-search', target: 'main', files: 8, findings: 2, status: 'Review needed', diff: 'const query = `SELECT * FROM invoices WHERE name LIKE \'%${search}%\'`' },
  { id: 'pr-279', number: 279, title: 'Rotate session signing keys', repository: 'auth-service', author: 'jordan-r', source: 'chore/key-rotation', target: 'main', files: 4, findings: 0, status: 'Passed', diff: 'const signingKey = await loadSigningKeyFromVault()' },
  { id: 'pr-276', number: 276, title: 'Update account export flow', repository: 'payments-api', author: 'maya-chen', source: 'fix/export-authz', target: 'main', files: 6, findings: 1, status: 'Review needed', diff: 'await assertAccountMember(user.id, accountId)' },
]

export const scanStages = [
  'Repository cloning',
  'Codebase analysis',
  'Architecture identification',
  'Attack surface mapping',
  'AI security test planning',
  'Test execution',
  'Vulnerability validation',
  'Report generation',
]
