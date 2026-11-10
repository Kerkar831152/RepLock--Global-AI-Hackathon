import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from app.schemas.security_analysis import (
    CodeFileInput,
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
    SecurityFinding,
)
from app.services.repository_download_service import (
    repository_download_service,
)
from app.services.research_service import ResearchService
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.security_analysis_service import security_analysis_service
from app.services.semgrep_service import SemgrepError, SemgrepService


class ScanContextTests(unittest.TestCase):
    def setUp(self):
        self.orchestrator = ScanOrchestrator()

    def test_entire_small_file_is_submitted(self):
        content = "\n".join(f"line {number}" for number in range(1, 84))

        self.assertLessEqual(
            len(content),
            self.orchestrator.MAX_AI_FILE_CHARS,
        )
        self.assertEqual(
            self.orchestrator._build_context(content, target_line=1),
            (content, 1),
        )

    def test_large_file_context_keeps_original_line_numbers(self):
        content = "\n".join(
            f"line {number:03d} {'x' * 100}"
            for number in range(1, 201)
        )

        context, start_line = self.orchestrator._build_context(
            content,
            target_line=100,
        )

        self.assertLessEqual(len(context), self.orchestrator.MAX_AI_FILE_CHARS)
        self.assertLess(start_line, 100)
        self.assertIn("line 100", context.splitlines()[100 - start_line])

    def test_selection_preserves_original_file_line_count(self):
        content = "\n".join(f"line {number}" for number in range(1, 84))

        selected = self.orchestrator._select_files(
            [{"path": "index.html", "content": content}],
            [],
        )

        self.assertEqual(selected[0]["content"], content)
        self.assertEqual(selected[0]["start_line"], 1)
        self.assertEqual(selected[0]["original_line_count"], 83)


class SecurityFindingValidationTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def _finding(line_start, line_end, evidence):
        return {
            "title": "Validated finding",
            "vulnerability_type": "test",
            "severity": "medium",
            "confidence": 0.9,
            "file_path": "index.html",
            "line_start": line_start,
            "line_end": line_end,
            "evidence": evidence,
            "description": "Test finding.",
            "remediation": "Test remediation.",
        }

    async def test_invalid_ranges_are_rejected_without_dropping_valid_findings(self):
        source = CodeFileInput(
            path="index.html",
            content="ten\neleven",
            start_line=10,
            original_line_count=83,
        )
        response = {
            "summary": "Assessment complete.",
            "findings": [
                self._finding(12, 12, "outside context"),
                self._finding(12, 11, "reversed"),
                self._finding(10, 10, "not in submitted source"),
                self._finding(10, 10, "ten"),
            ],
            "limitations": [],
        }

        with patch(
            "app.services.security_analysis_service.ai_service.generate",
            new=AsyncMock(return_value=json.dumps(response)),
        ):
            result = await security_analysis_service.analyze(
                SecurityAnalysisRequest(files=[source])
            )

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].line_start, 10)
        self.assertTrue(any(
            "index.html" in item
            and "received 12-12" in item
            and "allowed range 10-11" in item
            and "submitted context" in item
            for item in result.limitations
        ))
        self.assertTrue(any(
            "index.html" in item
            and "received 12-11" in item
            and "allowed range 10-11" in item
            for item in result.limitations
        ))
        self.assertEqual(len(result.limitations), 3)

    def test_original_file_bounds_are_strict(self):
        source = CodeFileInput(
            path="index.html",
            content="ten\neleven\ntwelve",
            start_line=10,
            original_line_count=11,
        )
        finding = SecurityFinding.model_validate(
            self._finding(12, 12, "twelve")
        )
        result = SecurityAnalysisResponse(
            summary="Assessment complete.",
            findings=[finding],
        )

        validated = security_analysis_service._validate_evidence(
            result,
            {"index.html": source},
            [],
        )

        self.assertEqual(validated.findings, [])
        self.assertIn("outside the original file", validated.limitations[0])


class SemgrepOutputTests(unittest.TestCase):
    def setUp(self):
        self.service = SemgrepService()
        self.root = Path("repository")

    def test_valid_semgrep_result_maps_to_internal_finding(self):
        output = json.dumps({
            "results": [{
                "path": "index.html",
                "check_id": "test.rule",
                "start": {"line": 7},
                "extra": {
                    "message": "Potential issue",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79"]},
                    "lines": "unsafe()",
                },
            }],
            "errors": [],
        }).encode("utf-8")

        result = self.service._parse_output(output, self.root)

        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["findings"][0]["file_path"], "index.html")
        self.assertEqual(result["findings"][0]["line_number"], 7)
        self.assertEqual(result["findings"][0]["severity"], "high")
        self.assertEqual(result["findings"][0]["rule_id"], "test.rule")

    def test_malformed_output_is_reported_as_semgrep_error(self):
        for output in (b"not json", b'{"errors": []}'):
            with self.subTest(output=output):
                with self.assertRaises(SemgrepError):
                    self.service._parse_output(output, self.root)

    def test_malformed_finding_is_skipped_and_reported(self):
        output = json.dumps({
            "results": [{
                "path": "index.html",
                "start": {"line": 0},
                "extra": {"message": "Malformed location"},
            }],
            "errors": [],
        }).encode("utf-8")

        result = self.service._parse_output(output, self.root)

        self.assertEqual(result["total_findings"], 1)
        self.assertEqual(result["findings"], [])
        self.assertTrue(result["errors"])

    def test_execution_failure_is_reported(self):
        async def create_process(*args, **kwargs):
            self.assertIn("scan", args)
            kwargs["stderr"].write(b"configuration failed")
            return SimpleNamespace(
                returncode=2,
                wait=AsyncMock(return_value=2),
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            executable = Path(directory) / "semgrep.exe"
            executable.touch()

            with (
                patch(
                    "app.services.semgrep_service.settings.SEMGREP_PATH",
                    str(executable),
                ),
                patch(
                    "app.services.semgrep_service.asyncio.create_subprocess_exec",
                    new=AsyncMock(side_effect=create_process),
                ),
            ):
                with self.assertRaisesRegex(
                    SemgrepError,
                    "configuration failed",
                ):
                    asyncio.run(self.service.scan(str(root)))

    def test_timeout_stops_the_semgrep_process(self):
        class TimedOutProcess:
            def __init__(self):
                self.returncode = None
                self.kill = Mock()
                self.wait_calls = 0

            async def wait(self):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    await asyncio.sleep(1)
                self.returncode = -9
                return self.returncode

        process = TimedOutProcess()

        async def create_process(*args, **kwargs):
            self.assertIn("scan", args)
            self.assertIn("cwd", kwargs)
            return process

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            executable = Path(directory) / "semgrep.exe"
            executable.touch()

            with (
                patch(
                    "app.services.semgrep_service.settings.SEMGREP_PATH",
                    str(executable),
                ),
                patch(
                    "app.services.semgrep_service.settings.SEMGREP_TIMEOUT",
                    0.001,
                ),
                patch(
                    "app.services.semgrep_service.asyncio.create_subprocess_exec",
                    new=AsyncMock(side_effect=create_process),
                ),
            ):
                with self.assertRaisesRegex(SemgrepError, "time limit"):
                    asyncio.run(self.service.scan(str(root)))

        process.kill.assert_called_once()
        self.assertEqual(process.wait_calls, 2)


class ScanOrchestrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_zero_findings_are_reported_as_inconclusive(self):
        orchestrator = ScanOrchestrator()
        analysis = SecurityAnalysisResponse(
            summary="No findings were validated.",
            findings=[],
        )

        with (
            patch.object(
                repository_download_service,
                "download",
                new=AsyncMock(return_value="a" * 40),
            ),
            patch(
                "app.services.scan_orchestrator.semgrep_service.scan",
                new=AsyncMock(return_value={
                    "findings": [],
                    "total_findings": 0,
                    "errors": [],
                }),
            ),
            patch.object(
                orchestrator,
                "_read_source_files",
                return_value=([{
                    "path": "index.html",
                    "content": "<html></html>",
                }], []),
            ),
            patch.object(
                orchestrator,
                "_select_files",
                return_value=[{
                    "path": "index.html",
                    "content": "<html></html>",
                    "start_line": 1,
                    "original_line_count": 1,
                }],
            ),
            patch.object(orchestrator, "_select_signals", return_value=[]),
            patch(
                "app.services.scan_orchestrator.security_analysis_service.analyze",
                new=AsyncMock(return_value=analysis),
            ),
        ):
            result = await orchestrator.run(SimpleNamespace(), "token")

        self.assertIn(
            "does not establish that the repository is free of vulnerabilities",
            " ".join(result["limitations"]),
        )


class TavilyConfigurationTests(unittest.IsolatedAsyncioTestCase):
    async def test_configured_api_key_is_sent_as_bearer_auth(self):
        with patch(
            "app.services.research_service.settings.TAVILY_API_KEY",
            "test-key",
        ):
            service = ResearchService()

        try:
            self.assertEqual(
                service.client.headers["Authorization"],
                "Bearer test-key",
            )
        finally:
            await service.close()


if __name__ == "__main__":
    unittest.main()
