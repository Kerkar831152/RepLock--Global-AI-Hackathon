import json
import unittest
from unittest.mock import AsyncMock, patch

from app.schemas.security_analysis import SecurityAnalysisResponse
from app.services.merge_intelligence_service import MergeIntelligenceService


class MergeIntelligenceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.service = MergeIntelligenceService()

    def _conflict_json(self, status="confirmed", confidence=0.95):
        return json.dumps({
            "summary": "The caller and provider now use incompatible contracts.",
            "conflicts": [{
                "status": status,
                "conflict_type": "api-contract",
                "confidence": confidence,
                "explanation": "The consumer still expects the old response shape.",
                "affected_files": ["api.py", "client.py"],
                "evidence": [
                    {
                        "branch": "main",
                        "file_path": "api.py",
                        "line_start": 10,
                        "line_end": 10,
                        "code": 'return {"id": user.id}',
                    },
                    {
                        "branch": "feature",
                        "file_path": "client.py",
                        "line_start": 20,
                        "line_end": 20,
                        "code": 'user["name"]',
                    },
                ],
            }],
        })

    def _branch_change(self, path, branch, line_number, code):
        return {
            "path": path,
            "branch": branch,
            "lines": [(line_number, code, True)],
            "changed_lines": {line_number},
            "added_source": code,
        }

    async def test_conflict_requires_verified_added_evidence_from_both_branches(self):
        changes_a = [
            self._branch_change("api.py", "main", 10, 'return {"id": user.id}')
        ]
        changes_b = [
            self._branch_change("client.py", "feature", 20, 'user["name"]')
        ]
        generate = patch(
            "app.services.merge_intelligence_service.ai_service.generate",
            new=AsyncMock(return_value=self._conflict_json()),
        )

        with generate:
            summary, conflicts = await self.service._analyze_conflicts(
                "main",
                "feature",
                changes_a,
                changes_b,
            )

        self.assertIn("incompatible contracts", summary)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].status, "confirmed")
        self.assertEqual(set(conflicts[0].affected_files), {"api.py", "client.py"})

    async def test_low_confidence_conflict_is_downgraded_to_potential(self):
        changes_a = [
            self._branch_change("api.py", "main", 10, 'return {"id": user.id}')
        ]
        changes_b = [
            self._branch_change("client.py", "feature", 20, 'user["name"]')
        ]
        generate = patch(
            "app.services.merge_intelligence_service.ai_service.generate",
            new=AsyncMock(
                return_value=self._conflict_json(
                    status="confirmed",
                    confidence=0.6,
                )
            ),
        )

        with generate:
            _, conflicts = await self.service._analyze_conflicts(
                "main",
                "feature",
                changes_a,
                changes_b,
            )

        self.assertEqual(conflicts[0].status, "potential")

    async def test_merge_analysis_compares_each_branch_to_common_ancestor(self):
        comparison = {
            "merge_base_commit": {"sha": "common"},
            "status": "diverged",
            "ahead_by": 2,
            "behind_by": 1,
            "files": [{
                "filename": "service.py",
                "status": "modified",
                "changes": 1,
                "patch": "@@ -1 +1 @@\n-return old()\n+return new()",
            }],
        }
        comparison_a = {
            "files": [{
                "filename": "api.py",
                "status": "modified",
                "changes": 1,
                "patch": "@@ -9 +10 @@\n-old()\n+return {\"id\": user.id}",
            }],
        }
        comparison_b = {
            "files": [{
                "filename": "client.py",
                "status": "modified",
                "changes": 1,
                "patch": "@@ -19 +20 @@\n-old()\n+user[\"name\"]",
            }],
        }
        compare = patch.object(
            self.service,
            "_get_comparison",
            new=AsyncMock(side_effect=[
                comparison,
                comparison_a,
                comparison_b,
            ]),
        )
        security = patch(
            "app.services.merge_intelligence_service.security_analysis_service.analyze",
            new=AsyncMock(return_value=SecurityAnalysisResponse(
                summary="No security issues found.",
                findings=[],
            )),
        )
        generate = patch(
            "app.services.merge_intelligence_service.ai_service.generate",
            new=AsyncMock(return_value=self._conflict_json()),
        )

        with compare as comparisons, security, generate:
            result = await self.service.analyze(
                "owner/repository",
                "token",
                "main",
                "feature",
            )

        self.assertEqual(comparisons.await_count, 3)
        self.assertEqual(comparisons.await_args_list[1].args[2], "common")
        self.assertEqual(comparisons.await_args_list[2].args[2], "common")
        self.assertEqual(len(result["conflicts"]), 1)
        self.assertEqual(result["changed_files"], 1)
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()
