
from dataclasses import dataclass
import re
from urllib.parse import quote

import httpx

from app.schemas.security_analysis import (
    CodeFileInput,
    SecurityAnalysisRequest,
    SecurityAnalysisResponse,
)
from app.services.security_analysis_service import (
    security_analysis_service,
    SecurityAnalysisError
)


class PullRequestError(Exception):
    pass


@dataclass(frozen=True)
class ChangedCode:
    source: CodeFileInput
    changed_lines: frozenset[int]
    added_source: str


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

            if response.status_code in {403, 429}:
                if (
                    response.status_code == 429
                    or response.headers.get("x-ratelimit-remaining") == "0"
                ):
                    reset = response.headers.get("x-ratelimit-reset")
                    retry_after = (
                        f" Try again after {reset}."
                        if reset and reset.isdigit()
                        else " Retry after the GitHub rate limit resets."
                    )
                    raise PullRequestError(
                        "GitHub API rate limit was reached." + retry_after
                    )
                raise PullRequestError(
                    "GitHub denied access to the pull request or repository."
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
        except httpx.TimeoutException as exc:
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

        return self._normalize_metadata(pull_request, number)

    @staticmethod
    def _normalize_metadata(pull_request: object, number: int) -> dict:
        if not isinstance(pull_request, dict):
            raise PullRequestError("GitHub returned invalid pull request metadata.")

        if pull_request.get("state") != "open":
            raise PullRequestError("Only open pull requests can be reviewed.")

        head = pull_request.get("head") or {}
        base = pull_request.get("base") or {}
        changed_files = pull_request.get("changed_files")

        if (
            not isinstance(head, dict)
            or not isinstance(head.get("sha"), str)
            or not head["sha"]
            or not isinstance(base, dict)
            or not isinstance(base.get("sha"), str)
            or not base["sha"]
        ):
            raise PullRequestError("Pull request commit references are unavailable.")

        if (
            not isinstance(changed_files, int)
            or isinstance(changed_files, bool)
            or changed_files < 0
        ):
            raise PullRequestError("GitHub returned an invalid changed-file count.")

        html_url = pull_request.get("html_url")
        if not isinstance(html_url, str) or not html_url:
            raise PullRequestError("GitHub returned an invalid pull request URL.")

        return {
            "number": number,
            "state": "open",
            "head_sha": head["sha"],
            "base_sha": base["sha"],
            "html_url": html_url,
            "changed_files": changed_files,
        }

    def _extract_hunk(
        self,
        patch: str,
        path: str
    ) -> ChangedCode | None:

        lines = patch.splitlines()

        for index, header in enumerate(lines):
            match = re.match(
                r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@",
                header
            )

            if not match:
                continue

            current_line = int(match.group(1))
            source_lines: list[str] = []
            changed_lines: set[int] = set()
            added_lines: list[str] = []
            total_chars = 0

            for diff_line in lines[index + 1:]:
                if diff_line.startswith("@@"):
                    break

                if diff_line.startswith("\\"):
                    continue

                if diff_line.startswith("-"):
                    continue
                if diff_line.startswith("+"):
                    source_line = diff_line[1:]
                    is_added = True
                elif diff_line.startswith(" "):
                    source_line = diff_line[1:]
                    is_added = False
                else:
                    break

                if total_chars + len(source_line) + 1 > self.MAX_FILE_CHARS:
                    break

                source_lines.append(source_line)
                if is_added:
                    changed_lines.add(current_line)
                    added_lines.append(source_line)
                total_chars += len(source_line) + 1
                current_line += 1

            if not source_lines or not changed_lines:
                continue

            try:
                source = CodeFileInput(
                    path=path,
                    content="\n".join(source_lines),
                    start_line=int(match.group(1)),
                )
            except ValueError:
                continue

            return ChangedCode(
                source=source,
                changed_lines=frozenset(changed_lines),
                added_source="\n".join(added_lines),
            )

        return None

    def _file_priority(self, item: dict) -> tuple:
        filename = item.get("filename")
        path = filename.lower() if isinstance(filename, str) else ""

        priority = sum(
            1 for name in self.PRIORITY_NAMES if name in path
        )

        additions = item.get("additions", 0)
        deletions = item.get("deletions", 0)
        changes = (
            additions + deletions
            if isinstance(additions, int)
            and not isinstance(additions, bool)
            and isinstance(deletions, int)
            and not isinstance(deletions, bool)
            else 0
        )

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
                item for item in result[:page_size]
                if isinstance(item, dict)
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
        metadata_url = base_url

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(30, connect=5)
        ) as client:
            files = await self._get_changed_files(
                client,
                base_url,
                token
            )

            latest_metadata = self._normalize_metadata(
                await self._get(client, metadata_url, token),
                number,
            )

        if (
            latest_metadata["head_sha"] != metadata["head_sha"]
            or latest_metadata["base_sha"] != metadata["base_sha"]
        ):
            raise PullRequestError(
                "The pull request changed during review. Retry to review its latest commit."
            )
        metadata = latest_metadata

        candidates = [
            item for item in files
            if item.get("status") != "removed"
            and isinstance(item.get("filename"), str)
            and item.get("filename")
            and isinstance(item.get("additions", 0), int)
            and not isinstance(item.get("additions", 0), bool)
            and isinstance(item.get("deletions", 0), int)
            and not isinstance(item.get("deletions", 0), bool)
            and item.get("additions", 0) + item.get("deletions", 0) > 0
            and isinstance(item.get("patch"), str)
        ]

        candidates.sort(key=self._file_priority)

        selected_files: list[ChangedCode] = []
        total_chars = 0

        for item in candidates:
            if len(selected_files) >= self.MAX_FILES:
                break

            try:
                changed_code = self._extract_hunk(
                    item["patch"],
                    item["filename"]
                )
            except ValueError:
                continue

            if changed_code is None:
                continue

            remaining = self.MAX_TOTAL_CHARS - total_chars

            if remaining <= 0:
                break

            if len(changed_code.source.content) > remaining:
                trimmed = changed_code.source.content[:remaining]
                trimmed = trimmed.rsplit("\n", 1)[0]

                if not trimmed:
                    break

                kept_line_count = len(trimmed.splitlines())
                last_line = (
                    changed_code.source.start_line + kept_line_count - 1
                )
                changed_code = ChangedCode(
                    source=changed_code.source.model_copy(
                        update={"content": trimmed}
                    ),
                    changed_lines=frozenset(
                        line for line in changed_code.changed_lines
                        if line <= last_line
                    ),
                    added_source=changed_code.added_source,
                )
                if not changed_code.changed_lines:
                    continue

            selected_files.append(changed_code)
            total_chars += len(changed_code.source.content)

        limitations = []
        if metadata["changed_files"] != len(files):
            limitations.append(
                f"GitHub reports {metadata['changed_files']} changed files, "
                f"but returned {len(files)} file records."
            )

        if not files:
            summary = (
                "This pull request contains no changed files."
                if metadata["changed_files"] == 0
                else "GitHub returned no changed-file records for this pull request."
            )
            findings = []
        elif not selected_files:
            summary = (
                "No analyzable added source-code lines were found in this "
                "pull request."
            )
            findings = []
            limitations.append(
                "Changed files were deleted, binary, unsupported, or did not "
                "include a usable text patch."
            )
        else:
            try:
                analysis = await security_analysis_service.analyze(
                    SecurityAnalysisRequest(
                        files=[item.source for item in selected_files],
                        research_query=(
                            "Assess only vulnerabilities introduced by the "
                            "added lines in these pull request diffs. "
                            "Treat unchanged context as context, not as a "
                            "newly introduced finding."
                        )
                    )
                )
            except SecurityAnalysisError as exc:
                raise PullRequestError(
                    "AI security analysis failed for this pull request."
                ) from exc

            had_findings = bool(analysis.findings)
            files_by_path = {
                item.source.path: item for item in selected_files
            }
            verified_findings = []
            for finding in analysis.findings:
                changed_file = files_by_path.get(finding.file_path)
                if not changed_file:
                    continue
                if not any(
                    finding.line_start <= line <= finding.line_end
                    for line in changed_file.changed_lines
                ):
                    continue

                evidence = " ".join(finding.evidence.split())
                added_source = " ".join(changed_file.added_source.split())
                if evidence and evidence in added_source:
                    verified_findings.append(finding)
                else:
                    limitations.append(
                        "A finding was excluded because its evidence did not "
                        "quote an added line in the pull request."
                    )

            analysis.findings = verified_findings
            if had_findings and not verified_findings:
                analysis.summary = (
                    "No vulnerabilities associated with added lines were "
                    "verified."
                )

            limitations.extend(analysis.limitations)

            limitations.append(
                "The review analyses at most three selected files and the "
                "first changed hunk from each selected file."
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

        if not files or not selected_files:
            analysis = SecurityAnalysisResponse(
                summary=summary,
                findings=findings,
                limitations=limitations,
            )

        return {
            "head_sha": metadata["head_sha"],
            "html_url": metadata["html_url"],
            "analysis": analysis,
            "changed_files": metadata["changed_files"],
            "files_analyzed": len(selected_files),
            "limitations": list(dict.fromkeys(limitations))
        }


pull_request_service = PullRequestService()
