import asyncio
import unittest
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from fastapi import HTTPException
from fastapi import BackgroundTasks

from app.api import scans as scans_api
from app.models import Finding, Scan
from app.schemas.scan import ScanCreate
from app.services.scan_orchestrator import ScanOrchestrationError


class ScanRunApiTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.repository = SimpleNamespace(
            id=uuid.uuid4(),
            full_name="owner/repository",
            default_branch="main",
        )
        self.current_user = SimpleNamespace(
            id=uuid.uuid4(),
            github_access_token_encrypted="encrypted-token",
        )
        self.scan_data = ScanCreate(
            repository_id=self.repository.id,
            scan_type="full",
        )
        self.db = Mock()
        self.scan = None

        def add(record):
            if isinstance(record, Scan):
                record.id = uuid.uuid4()
                self.scan = record
            elif isinstance(record, Finding):
                record.id = uuid.uuid4()
                record.status = "open"
                record.created_at = datetime.now(timezone.utc)

        def refresh(record):
            if isinstance(record, Scan):
                record.created_at = datetime.now(timezone.utc)

        self.db.add.side_effect = add
        self.db.refresh.side_effect = refresh
        self.db.scalar.return_value = None
        self.db.get.side_effect = lambda model, _id: (
            self.scan if model is Scan else None
        )

        self.repository_patch = patch.object(
            scans_api,
            "_get_owned_repository",
            return_value=self.repository,
        )
        self.token_patch = patch.object(
            scans_api,
            "decrypt_token",
            return_value="github-token",
        )
        self.repository_patch.start()
        self.token_patch.start()
        self.addCleanup(self.repository_patch.stop)
        self.addCleanup(self.token_patch.stop)

    async def test_persists_success_metadata_and_returns_matching_response(self):
        finding = SimpleNamespace(
            title="Validated issue",
            description="A reproducible issue.",
            severity="high",
            vulnerability_type="injection",
            file_path="src/main.py",
            line_start=12,
            evidence="unsafe call",
            remediation="Validate input.",
        )
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(return_value={
                "commit_sha": "a" * 40,
                "summary": "Assessment completed.",
                "findings": [finding],
                "semgrep_findings": 1,
                "files_analyzed": 3,
                "limitations": ["Only selected files were analyzed."],
            }),
        )

        with orchestrator:
            response = await scans_api.run_repository_scan(
                self.scan_data,
                self.db,
                self.current_user,
            )

        self.assertEqual(self.scan.status, "completed")
        self.assertEqual(self.scan.files_analyzed, 3)
        self.assertEqual(self.scan.semgrep_findings, 1)
        self.assertEqual(
            self.scan.limitations,
            ["Only selected files were analyzed."],
        )
        self.assertEqual(response.scan.status, "completed")
        self.assertEqual(response.files_analyzed, 3)
        self.assertEqual(response.semgrep_findings, 1)
        self.assertEqual(len(response.findings), 1)
        self.assertEqual(response.findings[0].file_path, "src/main.py")

    async def test_scanner_failure_is_persisted_as_failed(self):
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(
                side_effect=ScanOrchestrationError(
                    "Semgrep execution failed with exit code 2."
                )
            ),
        )

        with orchestrator:
            with self.assertRaises(HTTPException) as raised:
                await scans_api.run_repository_scan(
                    self.scan_data,
                    self.db,
                    self.current_user,
                )

        self.assertEqual(raised.exception.status_code, 502)
        self.assertIn("Semgrep execution failed", raised.exception.detail)
        self.assertEqual(self.scan.status, "failed")
        self.assertIn("Semgrep execution failed", self.scan.summary)

    async def test_cancelled_scan_is_persisted_as_failed(self):
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(side_effect=asyncio.CancelledError()),
        )

        with orchestrator:
            with self.assertRaises(asyncio.CancelledError):
                await scans_api.run_repository_scan(
                    self.scan_data,
                    self.db,
                    self.current_user,
                )

        self.assertEqual(self.scan.status, "failed")
        self.assertEqual(self.scan.summary, "Repository security scan was cancelled")

    async def test_background_scan_returns_pending_record_and_schedules_worker(self):
        background_tasks = BackgroundTasks()
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(),
        )

        with orchestrator as run:
            response = await scans_api.start_background_repository_scan(
                background_tasks,
                self.scan_data,
                self.db,
                self.current_user,
            )

        self.assertEqual(response.status, "pending")
        self.assertEqual(len(background_tasks.tasks), 1)
        self.assertIs(
            background_tasks.tasks[0].func,
            scans_api.execute_background_scan,
        )
        run.assert_not_awaited()

    async def test_background_worker_persists_results_with_its_own_session(self):
        scan = SimpleNamespace(
            id=uuid.uuid4(),
            status="pending",
        )
        worker_db = Mock()
        worker_db.get.return_value = scan
        worker = patch.object(
            scans_api,
            "SessionLocal",
            return_value=worker_db,
        )
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(return_value={
                "commit_sha": "b" * 40,
                "summary": "Background scan complete.",
                "findings": [],
                "semgrep_findings": 0,
                "files_analyzed": 2,
                "limitations": [],
            }),
        )

        with worker, orchestrator as run:
            await scans_api.execute_background_scan(
                scan.id,
                SimpleNamespace(
                    full_name="owner/repository",
                    default_branch="main",
                ),
                "github-token",
            )

        run.assert_awaited_once()
        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.commit_sha, "b" * 40)
        self.assertEqual(scan.files_analyzed, 2)
        self.assertEqual(worker_db.commit.call_count, 2)
        worker_db.close.assert_called_once()

    async def test_background_worker_persists_orchestration_failures(self):
        scan = SimpleNamespace(
            id=uuid.uuid4(),
            status="pending",
        )
        worker_db = Mock()
        worker_db.get.return_value = scan
        worker = patch.object(
            scans_api,
            "SessionLocal",
            return_value=worker_db,
        )
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(
                side_effect=ScanOrchestrationError("Semgrep failed")
            ),
        )

        with worker, orchestrator:
            await scans_api.execute_background_scan(
                scan.id,
                SimpleNamespace(
                    full_name="owner/repository",
                    default_branch="main",
                ),
                "github-token",
            )

        self.assertEqual(scan.status, "failed")
        self.assertEqual(scan.summary, "Semgrep failed")
        worker_db.close.assert_called_once()

    async def test_rejects_duplicate_active_scan_for_repository(self):
        self.db.scalar.return_value = uuid.uuid4()
        orchestrator = patch.object(
            scans_api.scan_orchestrator,
            "run",
            new=AsyncMock(),
        )

        with orchestrator as run:
            with self.assertRaises(HTTPException) as raised:
                await scans_api.run_repository_scan(
                    self.scan_data,
                    self.db,
                    self.current_user,
                )

        self.assertEqual(raised.exception.status_code, 409)
        run.assert_not_awaited()

    def test_manual_status_update_cannot_mark_running_scan_completed(self):
        running_scan = SimpleNamespace(status="running")
        owned_scan = patch.object(
            scans_api,
            "_get_owned_scan",
            return_value=running_scan,
        )

        with owned_scan:
            with self.assertRaises(HTTPException) as raised:
                scans_api.update_scan_status(
                    uuid.uuid4(),
                    scans_api.ScanStatusUpdate(status="completed"),
                    self.db,
                    self.current_user,
                )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("successful scan execution", raised.exception.detail)
        self.db.commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
