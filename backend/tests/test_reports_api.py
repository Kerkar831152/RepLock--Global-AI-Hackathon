import unittest
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import HTTPException

from app.api.dashboard import get_security_trends
from app.api.reports import get_repository_report


class ReportApiTests(unittest.TestCase):
    def setUp(self):
        self.user = SimpleNamespace(id=uuid.uuid4())
        self.repository = SimpleNamespace(
            id=uuid.uuid4(),
            owner_id=self.user.id,
            github_repo_id="123",
            name="repository",
            full_name="owner/repository",
            description="A test repository",
            default_branch="main",
            is_private=False,
        )
        self.scan = SimpleNamespace(
            id=uuid.uuid4(),
            repository_id=self.repository.id,
            status="completed",
            scan_type="full",
            commit_sha="abc123",
            pull_request_number=None,
            changed_files=None,
            files_analyzed=4,
            semgrep_findings=2,
            summary="Review summary",
            limitations=["Some files were not analyzed."],
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        self.finding = SimpleNamespace(
            id=uuid.uuid4(),
            scan_id=self.scan.id,
            title="SQL injection",
            description="Untrusted input reaches a query.",
            severity="high",
            vulnerability_type="SQL injection",
            status="open",
            file_path="src/db.py",
            line_number=12,
            evidence="execute(user_input)",
            remediation="Use parameterized queries.",
            created_at=datetime.now(timezone.utc),
        )

    def test_report_contains_evidence_locations_remediation_and_limitations(self):
        db = Mock()
        db.scalar.side_effect = [self.repository, self.scan]
        db.scalars.return_value.all.return_value = [self.finding]

        report = get_repository_report(
            self.repository.id,
            None,
            db,
            self.user,
        )

        self.assertEqual(report.repository.full_name, "owner/repository")
        self.assertEqual(report.scan.limitations, ["Some files were not analyzed."])
        self.assertEqual(report.total_findings, 1)
        self.assertEqual(report.findings_by_severity["high"], 1)
        self.assertEqual(report.findings[0].file_path, "src/db.py")
        self.assertEqual(report.findings[0].evidence, "execute(user_input)")
        self.assertEqual(
            report.findings[0].remediation,
            "Use parameterized queries.",
        )

    def test_report_hides_repositories_not_owned_by_the_user(self):
        db = Mock()
        db.scalar.return_value = None

        with self.assertRaises(HTTPException) as raised:
            get_repository_report(
                self.repository.id,
                None,
                db,
                self.user,
            )

        self.assertEqual(raised.exception.status_code, 404)
        db.scalars.assert_not_called()

    def test_trends_aggregate_stored_scan_and_finding_history(self):
        db = Mock()
        db.execute.return_value.all.return_value = [
            SimpleNamespace(
                date=date(2026, 11, 8),
                scans=2,
                findings=4,
                critical=1,
                high=2,
                unresolved=3,
            )
        ]

        response = get_security_trends(30, db, self.user)

        self.assertEqual(response.days, 30)
        self.assertEqual(len(response.items), 1)
        self.assertEqual(response.items[0].findings, 4)
        self.assertEqual(response.items[0].critical, 1)
        self.assertEqual(response.items[0].unresolved, 3)


if __name__ == "__main__":
    unittest.main()
