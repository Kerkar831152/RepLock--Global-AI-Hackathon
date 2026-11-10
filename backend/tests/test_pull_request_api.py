import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from app.api import pull_requests
from app.models import Scan
from app.schemas.security_analysis import SecurityAnalysisResponse


class PullRequestReviewCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.repository_id = uuid.uuid4()
        self.repository = SimpleNamespace(
            id=self.repository_id,
            full_name="owner/repository",
        )
        self.user = SimpleNamespace(
            github_access_token_encrypted="encrypted-token",
        )
        self.metadata = {
            "number": 2,
            "head_sha": "current-head",
            "base_sha": "base-head",
            "html_url": "https://github.com/owner/repository/pull/2",
            "changed_files": 2,
        }
        self.cached_scan = SimpleNamespace(
            id=uuid.uuid4(),
            repository_id=self.repository_id,
            pull_request_number=2,
            commit_sha="old-head",
            changed_files=1,
            files_analyzed=1,
            status="completed",
            scan_type="pull_request",
            review_version=pull_requests.PR_REVIEW_VERSION,
            summary="Old review",
            limitations=["Original limitations"],
        )

        class FakeDB:
            def __init__(inner_self):
                inner_self.added_scan = None

            def scalar(inner_self, statement):
                parameters = statement.compile().params
                requested_sha = next(
                    value
                    for key, value in parameters.items()
                    if "commit_sha" in key
                )
                requested_version = next(
                    value
                    for key, value in parameters.items()
                    if "review_version" in key
                )
                if (
                    requested_sha == self.cached_scan.commit_sha
                    and requested_version == self.cached_scan.review_version
                ):
                    return self.cached_scan
                return None

            def scalars(inner_self, _statement):
                return SimpleNamespace(all=lambda: [])

            def add(inner_self, record):
                if isinstance(record, Scan):
                    record.id = uuid.uuid4()
                    inner_self.added_scan = record

            def commit(inner_self):
                return None

            def refresh(inner_self, _record):
                return None

            def rollback(inner_self):
                return None

        self.db = FakeDB()

    def _patch_dependencies(self, review):
        return (
            patch.object(
                pull_requests,
                "get_owned_repository",
                return_value=self.repository,
            ),
            patch.object(
                pull_requests,
                "get_github_token",
                return_value="github-token",
            ),
            patch.object(
                pull_requests.pull_request_service,
                "get_pull_request_metadata",
                new=AsyncMock(return_value=self.metadata),
            ),
            patch.object(
                pull_requests.pull_request_service,
                "review_pull_request",
                new=AsyncMock(return_value=review),
            ),
        )

    async def test_same_head_commit_reuses_saved_review(self):
        self.metadata["head_sha"] = self.cached_scan.commit_sha
        patches = self._patch_dependencies(review=None)

        with patches[0], patches[1], patches[2], patches[3] as run_review:
            response = await pull_requests.review_pull_request(
                self.repository_id,
                2,
                self.db,
                self.user,
            )

        run_review.assert_not_awaited()
        self.assertEqual(response.head_sha, self.cached_scan.commit_sha)
        self.assertEqual(response.changed_files, 1)
        self.assertIn("Original limitations", response.limitations)
        self.assertTrue(any("previously saved" in item for item in response.limitations))

    async def test_changed_head_commit_bypasses_old_review_cache(self):
        review = {
            "head_sha": self.metadata["head_sha"],
            "html_url": self.metadata["html_url"],
            "analysis": SecurityAnalysisResponse(
                summary="Fresh review",
                findings=[],
            ),
            "changed_files": 2,
            "files_analyzed": 2,
            "limitations": [],
        }
        patches = self._patch_dependencies(review)

        with patches[0], patches[1], patches[2], patches[3] as run_review:
            response = await pull_requests.review_pull_request(
                self.repository_id,
                2,
                self.db,
                self.user,
            )

        run_review.assert_awaited_once()
        self.assertEqual(response.head_sha, "current-head")
        self.assertEqual(response.changed_files, 2)
        self.assertIsNotNone(self.db.added_scan)
        self.assertEqual(self.db.added_scan.commit_sha, "current-head")
        self.assertEqual(self.db.added_scan.changed_files, 2)

    async def test_legacy_same_head_review_is_reanalyzed(self):
        self.metadata["head_sha"] = self.cached_scan.commit_sha
        self.cached_scan.review_version = None
        review = {
            "head_sha": self.metadata["head_sha"],
            "html_url": self.metadata["html_url"],
            "analysis": SecurityAnalysisResponse(
                summary="Revalidated review",
                findings=[],
            ),
            "changed_files": 2,
            "files_analyzed": 1,
            "limitations": [],
        }
        patches = self._patch_dependencies(review)

        with patches[0], patches[1], patches[2], patches[3] as run_review:
            response = await pull_requests.review_pull_request(
                self.repository_id,
                2,
                self.db,
                self.user,
            )

        run_review.assert_awaited_once()
        self.assertEqual(response.summary, "Revalidated review")
        self.assertEqual(response.head_sha, self.cached_scan.commit_sha)


if __name__ == "__main__":
    unittest.main()
