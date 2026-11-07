
import re
from urllib.parse import quote

import httpx

from app.schemas.security_analysis import (
    CodeFileInput,
    ScannerSignalInput,
    SecurityAnalysisRequest
)
from app.services.security_analysis_service import (
    security_analysis_service,
    SecurityAnalysisError
)


class PullRequestError(Exception):
    pass


class PullRequestService:

    GITHUB_API = "https://api.github.com"
    MAX_FILES = 3
    MAX_FILE_CHARS = 4000
    MAX_TOTAL_CHARS = 8000
    MAX_DIFF_FILES = 30

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
        token: str,
        params: dict | None = None
    ):
        try:
            response = await client.get(
                url,
                headers=self._headers(token),
                params=params
            )

            if response.status_code == 401:
                raise PullRequestError(
                    "GitHub authorization expired. Reconnect GitHub."
                )

            if response.status_code == 403:
                raise PullRequestError(
                    "GitHub denied access or the API rate limit was reached."
                )

            if response.status_code == 404:
                raise PullRequestError(
                    "Pull request or repository was not found or is inaccessible."
                )

            response.raise_for_status()
            return response.json()

        except PullRequestError:
            raise
        except httpx.TimeoutException as exc:
            raise PullRequestError("GitHub API request timed out") from exc
        except httpx.HTTPError as exc:
            raise PullRequestError("Unable to communicate with GitHub") from exc

    async def list_pull_requests(
        self,
        full_name: str,
        token: str
    ) -> list[dict]:

        repository = quote(full_name, safe="/")
        url = f"{self.GITHUB_API}/repos/{repository}/pulls"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20, connect=5)
        ) as client:
            result = await self._get(
                client,
                url,
                token,
                params={
                    "state": "open",
                    "sort": "updated",
                    "direction": "desc",
                    "per_page": 20
                }
            )

        return [
            {
                "number": item["number"],
                "title": item["title"],
                "state": item["state"],
                "html_url": item["html_url"],
                "author": (
                    item.get("user", {}).get("login")
                    if item.get("user") else None
                ),
                "head_sha": item["head"]["sha"],
                "base_branch": item["base"]["ref"],
                "changed_files": item.get("changed_files", 0),
                "additions": item.get("additions", 0),
                "deletions": item.get("deletions", 0)
            }
            for item in result
        ]

    def _extract_hunk(
        self,
        patch: str,
        path: str
    ) -> CodeFileInput | None:

        lines = patch.splitlines()

        for index, header in enumerate(lines):
            match = re.match(
                r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@",
                header
            )

            if not match:
                continue

            start_line = int(match.group(1))
            expected_lines = int(match.group(2) or 1)

            source_lines = []
            current_line = start_line
            consumed = 0
            total_chars = 0

            for diff_line in lines[index + 1:]:
                if diff_line.startswith("@@"):
                    break

                if diff_line.startswith("\\"):
                    continue

                if diff_line.startswith(" "):
                    source_line = diff_line[1:]
                elif diff_line.startswith("+"):
                    source_line = diff_line[1:]
                elif diff_line.startswith("-"):
                    continue
                else:
                    break

                if total_chars + len(source_line) + 1 > self.MAX_FILE_CHARS:
                    break

                source_lines.append(source_line)
                total_chars += len(source_line) + 1
                current_line += 1
                consumed += 1

                if consumed >= expected_lines:
                    break

            if not source_lines:
                return None

            return CodeFileInput(
                path=path,
                content="\n".join(source_lines),
                start_line=start_line
            )

        return None

    async def review_pull_request(
        self,
        full_name: str,
        number: int,
        token: str
    ):

        repository = quote(full_name, safe="/")
        base_url = f"{self.GITHUB_API}/repos/{repository}/pulls/{number}"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=5)
        ) as client:
            pull_request = await self._get(
                client,
                base_url,
                token
            )

            if pull_request.get("state") != "open":
                raise PullRequestError(
                    "Only open pull requests can be reviewed."
                )

            files = await self._get(
                client,
                f"{base_url}/files",
                token,
                params={"per_page": self.MAX_DIFF_FILES}
            )

        selected_files = []
        scanner_signals = []
        total_chars = 0

        for item in files:
            if len(selected_files) >= self.MAX_FILES:
                break

            if item.get("status") == "removed":
                continue

            if item.get("additions", 0) + item.get("deletions", 0) == 0:
                continue

            patch = item.get("patch")

            if not patch:
                continue

            try:
                code_file = self._extract_hunk(
                    patch,
                    item["filename"]
                )
            except ValueError:
                continue

            if code_file is None:
                continue

            remaining = self.MAX_TOTAL_CHARS - total_chars

            if remaining <= 0:
                break

            if len(code_file.content) > remaining:
                trimmed = code_file.content[:remaining]
                trimmed = trimmed.rsplit("\n", 1)[0]

                if not trimmed:
                    break

                code_file.content = trimmed

            selected_files.append(code_file)
            total_chars += len(code_file.content)

            scanner_signals.append(
                ScannerSignalInput(
                    title="Pull request code change",
                    description=(
                        f"This file was modified in the pull request. "
                        f"GitHub reports {item.get('additions', 0)} additions "
                        f"and {item.get('deletions', 0)} deletions. "
                        "Review the submitted code for security implications."
                    ),
                    file_path=item["filename"]
                )
            )

        if not selected_files:
            raise PullRequestError(
                "No supported code diff hunks were available for analysis."
            )

        try:
            analysis = await security_analysis_service.analyze(
                SecurityAnalysisRequest(
                    files=selected_files,
                    scanner_findings=scanner_signals[:5]
                )
            )
        except SecurityAnalysisError as exc:
            raise PullRequestError(
                "AI security analysis failed for this pull request."
            ) from exc

        limitations = list(analysis.limitations)
        limitations.append(
            "MVP review analyses at most three files and the first diff "
            "hunk from each selected file."
        )

        return {
            "head_sha": pull_request["head"]["sha"],
            "html_url": pull_request["html_url"],
            "analysis": analysis,
            "files_analyzed": len(selected_files),
            "limitations": list(dict.fromkeys(limitations))
        }


pull_request_service = PullRequestService()
