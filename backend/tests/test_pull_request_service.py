import unittest
from unittest.mock import AsyncMock, patch

from app.schemas.security_analysis import (
    SecurityAnalysisResponse,
    SecurityFinding,
)
from app.services.pull_request_service import (
    PullRequestError,
    PullRequestService,
)


class PullRequestServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = PullRequestService()
        self.metadata = {
            "number": 2,
            "state": "open",
            "head_sha": "head-sha",
            "base_sha": "base-sha",
            "html_url": "https://github.com/owner/repo/pull/2",
            "changed_files": 1,
        }

    def test_extract_hunk_tracks_added_line_numbers_and_path(self):
        changed = self.service._extract_hunk(
            "@@ -8,3 +8,4 @@\n"
            " context_before()\n"
            "-old_call()\n"
            "+new_call()\n"
            " context_after()",
            "renamed/module.py",
        )

        self.assertIsNotNone(changed)
        self.assertEqual(changed.source.path, "renamed/module.py")
        self.assertEqual(changed.source.start_line, 8)
        self.assertEqual(changed.changed_lines, frozenset({9}))
        self.assertEqual(changed.added_source, "new_call()")

    def test_metadata_requires_head_base_and_accurate_changed_file_count(self):
        metadata = {
            "state": "open",
            "head": {"sha": "head"},
            "base": {"sha": "base"},
            "changed_files": 0,
            "html_url": "https://github.com/owner/repo/pull/2",
        }

        normalized = self.service._normalize_metadata(metadata, 2)

        self.assertEqual(normalized["changed_files"], 0)
        self.assertEqual(normalized["head_sha"], "head")
        self.assertEqual(normalized["base_sha"], "base")

        metadata["changed_files"] = -1
        with self.assertRaises(PullRequestError):
            self.service._normalize_metadata(metadata, 2)

    async def test_changed_files_are_retrieved_with_api_pagination(self):
        first_page = [{"filename": f"file-{index}.py"} for index in range(100)]
        second_page = [{"filename": "file-100.py"}]
        get = patch.object(
            self.service,
            "_get",
            new=AsyncMock(side_effect=[first_page, second_page]),
        )

        with get as request:
            files = await self.service._get_changed_files(
                object(),
                "https://api.github.com/repos/owner/repo/pulls/2",
                "token",
            )

        self.assertEqual(len(files), 101)
        self.assertEqual(
            [call.kwargs["params"]["page"] for call in request.await_args_list],
            [1, 2],
        )

    async def test_empty_pull_request_succeeds_without_ai(self):
        get = patch.object(
            self.service,
            "_get",
            new=AsyncMock(side_effect=[
                [],
                {
                    "state": "open",
                    "head": {"sha": "head-sha"},
                    "base": {"sha": "base-sha"},
                    "changed_files": 0,
                    "html_url": self.metadata["html_url"],
                },
            ]),
        )
        analyze = patch(
            "app.services.pull_request_service.security_analysis_service.analyze",
            new=AsyncMock(),
        )

        with get, analyze as ai:
            result = await self.service.review_pull_request(
                "owner/repo",
                2,
                "token",
                metadata={**self.metadata, "changed_files": 0},
            )

        self.assertEqual(result["changed_files"], 0)
        self.assertEqual(result["files_analyzed"], 0)
        self.assertEqual(result["analysis"].findings, [])
        self.assertIn("no changed files", result["analysis"].summary)
        ai.assert_not_awaited()

    async def test_deleted_files_are_reported_as_unanalyzable_not_errors(self):
        deleted = {
            "filename": "old.py",
            "status": "removed",
            "additions": 0,
            "deletions": 4,
        }
        get = patch.object(
            self.service,
            "_get",
            new=AsyncMock(side_effect=[
                [deleted],
                {
                    "state": "open",
                    "head": {"sha": "head-sha"},
                    "base": {"sha": "base-sha"},
                    "changed_files": 1,
                    "html_url": self.metadata["html_url"],
                },
            ]),
        )

        with get:
            result = await self.service.review_pull_request(
                "owner/repo",
                2,
                "token",
                metadata=self.metadata,
            )

        self.assertEqual(result["changed_files"], 1)
        self.assertEqual(result["files_analyzed"], 0)
        self.assertEqual(result["analysis"].findings, [])
        self.assertTrue(result["limitations"])

    async def test_only_findings_quoting_added_lines_are_kept(self):
        patch_text = (
            "@@ -10,2 +10,3 @@\n"
            " cursor.execute(user_input)\n"
            "+cursor.execute(parameterized_query, (user_input,))\n"
            " return result"
        )
        changed_file = {
            "filename": "src/db.py",
            "status": "modified",
            "additions": 1,
            "deletions": 0,
            "patch": patch_text,
        }
        get = patch.object(
            self.service,
            "_get",
            new=AsyncMock(side_effect=[
                [changed_file],
                {
                    "state": "open",
                    "head": {"sha": "head-sha"},
                    "base": {"sha": "base-sha"},
                    "changed_files": 1,
                    "html_url": self.metadata["html_url"],
                },
            ]),
        )
        existing_context_finding = SecurityFinding(
            title="Existing injection",
            vulnerability_type="SQL injection",
            severity="high",
            confidence=0.9,
            file_path="src/db.py",
            line_start=10,
            line_end=10,
            evidence="cursor.execute(user_input)",
            description="Unsafe query.",
            remediation="Use parameters.",
        )
        added_line_finding = SecurityFinding(
            title="New issue",
            vulnerability_type="SQL injection",
            severity="high",
            confidence=0.9,
            file_path="src/db.py",
            line_start=11,
            line_end=11,
            evidence="cursor.execute(parameterized_query, (user_input,))",
            description="Unsafe query.",
            remediation="Use parameters.",
        )
        analysis = SecurityAnalysisResponse(
            summary="Potential problems found.",
            findings=[existing_context_finding, added_line_finding],
        )
        analyze = patch(
            "app.services.pull_request_service.security_analysis_service.analyze",
            new=AsyncMock(return_value=analysis),
        )

        with get, analyze:
            result = await self.service.review_pull_request(
                "owner/repo",
                2,
                "token",
                metadata=self.metadata,
            )

        self.assertEqual(len(result["analysis"].findings), 1)
        self.assertEqual(
            result["analysis"].findings[0].line_start,
            11,
        )

    async def test_pull_request_head_change_during_retrieval_fails_review(self):
        changed_head = {
            "state": "open",
            "head": {"sha": "new-head"},
            "base": {"sha": "base-sha"},
            "changed_files": 1,
            "html_url": self.metadata["html_url"],
        }
        get = patch.object(
            self.service,
            "_get",
            new=AsyncMock(side_effect=[
                [],
                changed_head,
            ]),
        )

        with get:
            with self.assertRaisesRegex(PullRequestError, "changed during review"):
                await self.service.review_pull_request(
                    "owner/repo",
                    2,
                    "token",
                    metadata=self.metadata,
                )


if __name__ == "__main__":
    unittest.main()
