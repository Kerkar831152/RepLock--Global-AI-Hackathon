
import re
from urllib.parse import quote

import httpx

from app.schemas.security_analysis import (
    CodeFileInput,
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

    MAX_DIFF_FILES = 300
    FILES_PER_PAGE = 100

    PRIORITY_NAMES = (
        "auth", "login", "user", "route", "api",
        "database", "db", "security", "config",
        "payment", "admin", "permission", "token",
        "session", "crypto"
    )

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

            data = response.json()

            if not isinstance(data, (dict, list)):
                raise PullRequestError("GitHub returned an invalid response.")

            return data

        except PullRequestError:
            raise
        except (httpx.TimeoutException, httpx.TimeoutException) as exc:
            raise PullRequestError(
                "GitHub API request timed out."
            ) from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise PullRequestError(
                "Unable to communicate with GitHub."
            ) from exc

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

        if not isinstance(result, list):
            raise PullRequestError("GitHub returned an invalid pull request list.")

        pull_requests = []

        for item in result:
            if not isinstance(item, dict):
                continue

            head = item.get("head") or {}
            base = item.get("base") or {}
            user = item.get("user") or {}

            if not isinstance(head, dict) or not isinstance(base, dict):
                continue

            if not item.get("number") or not head.get("sha"):
                continue

            pull_requests.append({
                "number": item["number"],
                "title": item.get("title", ""),
                "state": item.get("state", "open"),
                "html_url": item.get("html_url", ""),
                "author": user.get("login") if isinstance(user, dict) else None,
                "head_sha": head["sha"],
                "base_branch": base.get("ref", ""),
                "changed_files": item.get("changed_files", 0),
                "additions": item.get("additions", 0),
                "deletions": item.get("deletions", 0)
            })

        return pull_requests

    async def get_pull_request_metadata(
        self,
        full_name: str,
        number: int,
        token: str
    ) -> dict:

        repository = quote(full_name, safe="/")
        url = f"{self.GITHUB_API}/repos/{repository}/pulls/{number}"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(20, connect=5)
        ) as client:
            pull_request = await self._get(client, url, token)

        if not isinstance(pull_request, dict):
            raise PullRequestError("GitHub returned invalid pull request metadata.")

        if pull_request.get("state") != "open":
            raise PullRequestError(
                "Only open pull requests can be reviewed."
            )

        head = pull_request.get("head") or {}

        if not isinstance(head, dict) or not head.get("sha"):
            raise PullRequestError("Pull request head commit is unavailable.")

        return {
            "number": number,
            "state": pull_request["state"],
            "head_sha": head["sha"],
            "html_url": pull_request["html_url"],
            "changed_files": pull_request.get("changed_files", 0)
        }

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
            total_chars = 0

            for diff_line in lines[index + 1:]:
                if diff_line.startswith("@@"):
                    break

                if diff_line.startswith("\\"):
                    continue

                if diff_line.startswith((" ", "+")):
                    source_line = diff_line[1:]
                elif diff_line.startswith("-"):
                    continue
                else:
                    break

                if total_chars + len(source_line) + 1 > self.MAX_FILE_CHARS:
                    break

                source_lines.append(source_line)
                total_chars += len(source_line) + 1

                if len(source_lines) >= expected_lines:
                    break

            if not source_lines:
                return None

            return CodeFileInput(
                path=path,
                content="\n".join(source_lines),
                start_line=start_line
            )

        return None

    def _file_priority(self, item: dict) -> tuple:
        path = item.get("filename", "").lower()

        priority = sum(
            1 for name in self.PRIORITY_NAMES if name in path
        )

        changes = item.get("additions", 0) + item.get("deletions", 0)

        return (-priority, -changes, path)

    async def _get_changed_files(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        token: str
    ) -> list[dict]:

        all_files = []

        for page in range(1, 4):
            remaining = self.MAX_DIFF_FILES - len(all_files)

            if remaining <= 0:
                break

            page_size = min(self.FILES_PER_PAGE, remaining)

            result = await self._get(
                client,
                f"{base_url}/files",
                token,
                params={
                    "per_page": page_size,
                    "page": page
                }
            )

            if not isinstance(result, list):
                raise PullRequestError("GitHub returned an invalid changed-files list.")

            if not result:
                break

            all_files.extend(
                item for item in result if isinstance(item, dict)
            )

            if len(result) < page_size:
                break

        return all_files

    async def review_pull_request(
        self,
        full_name: str,
        number: int,
        token: str,
        metadata: dict | None = None
    ):

        if metadata is None:
            metadata = await self.get_pull_request_metadata(
                full_name,
                number,
                token
            )

        repository = quote(full_name, safe="/")
        base_url = f"{self.GITHUB_API}/repos/{repository}/pulls/{number}"

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=5)
        ) as client:
            files = await self._get_changed_files(
                client,
                base_url,
                token
            )

        candidates = [
            item for item in files
            if item.get("status") != "removed"
            and isinstance(item.get("additions", 0), int)
            and isinstance(item.get("deletions", 0), int)
            and item.get("additions", 0) + item.get("deletions", 0) > 0
            and isinstance(item.get("patch"), str)
            and item.get("filename")
        ]

        candidates.sort(key=self._file_priority)

        selected_files = []
        total_chars = 0

        for item in candidates:
            if len(selected_files) >= self.MAX_FILES:
                break

            try:
                code_file = self._extract_hunk(
                    item["patch"],
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

        if not selected_files:
            raise PullRequestError(
                "No supported code diff hunks were available for analysis."
            )

        try:
            analysis = await security_analysis_service.analyze(
                SecurityAnalysisRequest(
                    files=selected_files,
                    research_query=(
                        "Research security vulnerabilities and secure coding "
                        "practices relevant to these pull request code changes."
                    )
                )
            )
        except SecurityAnalysisError as exc:
            raise PullRequestError(
                "AI security analysis failed for this pull request."
            ) from exc

        limitations = list(analysis.limitations)

        limitations.append(
            "The review analyses at most three selected files and the first "
            "diff hunk from each selected file."
        )

        if metadata["changed_files"] > self.MAX_DIFF_FILES:
            limitations.append(
                f"GitHub reported {metadata['changed_files']} changed files. "
                f"Only the first {self.MAX_DIFF_FILES} were considered."
            )

        if len(candidates) > self.MAX_FILES:
            limitations.append(
                "Only three files are sent to the AI. Security-sensitive "
                "paths and larger changes are prioritised."
            )

        if len(files) < metadata["changed_files"] and len(files) < self.MAX_DIFF_FILES:
            limitations.append(
                "GitHub did not return all files reported in the pull request."
            )

        return {
            "head_sha": metadata["head_sha"],
            "html_url": metadata["html_url"],
            "analysis": analysis,
            "files_analyzed": len(selected_files),
            "limitations": list(dict.fromkeys(limitations))
        }


pull_request_service = PullRequestService()
