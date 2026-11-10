# RepLock

RepLock is a locally run GitHub repository security platform. It connects a GitHub account, scans connected repositories with Semgrep and AI-assisted validation, tracks findings and scan history, reviews pull requests, analyzes semantic branch conflicts, and exports scan reports.

## Architecture

- **Frontend:** React 19, TypeScript, Vite, React Router, TanStack Query, Axios, Recharts.
- **Backend:** FastAPI, SQLAlchemy, Pydantic, Alembic.
- **Database:** PostgreSQL.
- **Repository access:** GitHub OAuth and GitHub REST API.
- **Static analysis:** Semgrep CLI.
- **AI analysis:** Bifrost OpenAI-compatible gateway.
- **Research enrichment:** Tavily (optional).

The browser calls the FastAPI service directly. PostgreSQL stores users, connected repositories, scans, and findings. The API listens on `http://localhost:8000`; Vite listens on `http://localhost:5173`.

## API surface

Authenticated routes use `Authorization: Bearer <JWT>`. OAuth routes are browser redirects. OpenAPI provides the full schemas at `/docs`.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Backend health check |
| `GET` | `/api/v1/auth/github/login` | Begin GitHub OAuth |
| `GET` | `/api/v1/auth/github/callback` | Complete GitHub OAuth and return a frontend JWT |
| `GET` | `/api/v1/auth/me` | Current authenticated account |
| `GET` | `/api/v1/repositories/github?page=&per_page=` | List accessible GitHub repositories |
| `GET`, `POST` | `/api/v1/repositories/` | List or connect repositories |
| `GET` | `/api/v1/scans/` | Read scan history |
| `POST` | `/api/v1/scans/background` | Queue an in-process scan and return its record |
| `POST` | `/api/v1/scans/run` | Run a scan synchronously |
| `GET` | `/api/v1/scans/{scan_id}` | Poll a scan |
| `GET` | `/api/v1/findings/` | List and filter findings |
| `GET` | `/api/v1/findings/summary` | Finding totals by severity and status |
| `PATCH` | `/api/v1/findings/{finding_id}/status` | Update finding status |
| `GET` | `/api/v1/dashboard/overview` | Dashboard metrics and recent activity |
| `GET` | `/api/v1/dashboard/trends?days=30` | Stored scan and finding trends |
| `GET` | `/api/v1/repositories/{repository_id}/pull-requests` | List repository pull requests |
| `POST` | `/api/v1/repositories/{repository_id}/pull-requests/{number}/review` | Review the current pull request head |
| `POST` | `/api/v1/repositories/{repository_id}/merge-intelligence/analyze` | Analyze security and logical merge conflicts |
| `GET` | `/api/v1/reports/repositories/{repository_id}?scan_id={scan_id}` | Retrieve a scan report for download |

## Features

- GitHub OAuth login and authenticated repository connection.
- Repository scans using Semgrep and Bifrost-backed finding analysis.
- Persistent scan history, findings, evidence, status updates, and remediation details.
- Pull request reviews tied to the current PR head commit, with same-head review caching.
- Branch security analysis and AI-assisted logical merge-conflict results.
- Dashboard statistics, severity distribution, recent activity, and stored scan trends.
- Authorized repository security reports downloadable as Markdown.
- Responsive frontend pages for overview, repositories, scans, findings, pull requests, merge intelligence, reports, and settings.

## Prerequisites

- Windows PowerShell (commands below use Windows paths), Python 3.11 or newer.
- Node.js 22 LTS and npm.
- PostgreSQL installed and running locally.
- A GitHub OAuth App.
- A reachable Bifrost gateway and configured model for AI-backed analysis.
- A Tavily API key only if you want external research enrichment.
- Semgrep installed in the repository-local environment described below.

No Docker or cloud deployment is required.

## Configuration

1. Copy the root example file and edit it:

   ```powershell
   Copy-Item .env.example .env
   ```

2. Set `DATABASE_URL` to your local PostgreSQL database.
3. In GitHub Developer Settings, create an OAuth App with:
   - Homepage URL: `http://localhost:5173`
   - Authorization callback URL: `http://localhost:8000/api/v1/auth/github/callback`
4. Fill in `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
5. Generate fresh encryption and JWT secrets in the project virtual environment:

   ```powershell
   .\replock_env\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   .\replock_env\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Put the first value in `FERNET_KEY` and the second in `JWT_SECRET_KEY`. Keep `.env` private and do not commit it.
6. Configure `BIFROST_BASE_URL`, `BIFROST_API_KEY`, and `AI_MODEL` for your Bifrost installation. Scanning requires the AI gateway; a missing or unavailable required scan stage is reported as a failed scan.
7. `TAVILY_API_KEY` is optional. Without it, analysis can proceed without research enrichment and will report applicable limitations.
8. The frontend defaults to the local API origin. Set `VITE_API_URL` if the backend uses another local port.

The backend reads the root `.env`. The frontend reads Vite variables from `frontend/.env.local`; copy `frontend/.env.example` there if you need to override `VITE_API_URL`.

## Database setup

Create a local database using your PostgreSQL installation. For example, from PowerShell with `psql` on `PATH`:

```powershell
psql -U postgres -c "CREATE DATABASE replock;"
```

After configuring `DATABASE_URL`, apply the existing Alembic migrations:

```powershell
Set-Location backend
..\replock_env\Scripts\python.exe -m alembic upgrade head
Set-Location ..
```

Migrations are versioned under `backend/migrations/versions`. Apply them to an existing database; do not recreate a database that contains records you need to keep.

## Backend setup

From the repository root:

```powershell
py -3.11 -m venv replock_env
.\replock_env\Scripts\python.exe -m pip install --upgrade pip
.\replock_env\Scripts\python.exe -m pip install -r backend\requirements.txt
```

The default Windows Semgrep path is `semgrep_env\Scripts\semgrep.exe`. To keep the analyzer separate from backend dependencies and use that default, install it into the `semgrep_env` environment instead:

```powershell
py -3.11 -m venv semgrep_env
.\semgrep_env\Scripts\python.exe -m pip install semgrep
```

Then run the API from the backend directory:

```powershell
Set-Location backend
..\replock_env\Scripts\python.exe -m alembic upgrade head
..\replock_env\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check: `http://localhost:8000/health`. Interactive API documentation: `http://localhost:8000/docs`.

## Frontend setup

In another PowerShell window:

```powershell
Set-Location frontend
npm ci
npm run dev -- --host 127.0.0.1
```

Open `http://localhost:5173`. Sign in with GitHub, connect a repository, then start scans or reviews from the application.

## Running the application locally

1. Start PostgreSQL.
2. Start the configured Bifrost gateway and make sure its model is reachable. Tavily is optional.
3. Start the FastAPI backend on `127.0.0.1:8000`.
4. Start Vite on `127.0.0.1:5173`.
5. Complete GitHub OAuth in the browser.

The backend CORS allowlist includes `localhost:5173` and `127.0.0.1:5173`. When changing the Vite origin, update the backend CORS configuration accordingly.

## Testing and quality checks

Backend tests (run from the repository root):

```powershell
.\replock_env\Scripts\python.exe -m pip install pytest
Set-Location backend
..\replock_env\Scripts\python.exe -m pytest -q
Set-Location ..
```

Frontend checks:

```powershell
Set-Location frontend
npm run build
npm run lint
```

Tests that mock GitHub, Bifrost, and Tavily validate internal request handling only; they do not prove the live providers are configured or reachable. Live OAuth, GitHub repository operations, Semgrep execution, Bifrost analysis, and Tavily enrichment require local credentials/services.

## Operational limitations

- Background scans run in the API process and are not durable across backend restarts. A persistent task queue is not configured.
- There is no API rate limiter, and scan concurrency limits are per API process. Run one API worker for the intended local setup.
- Dynamic scanning is not available; supported scan types are full and static.
- Live integration behavior depends on local PostgreSQL, GitHub OAuth/API access, Semgrep, and Bifrost configuration. Tavily enrichment is optional.
- The frontend currently has build and lint checks but no dedicated automated component-test runner.
