import re
from urllib.parse import quote

import httpx

from app.schemas.security_analysis import (
    CodeFileInput,
    SecurityAnalysisRequest,
)
from app.services.security_analysis_service import (
    security_analysis_service,
    SecurityAnalysisError,
)


class MergeIntelligenceError(Exception):
    pass


class MergeIntelligenceService:
    GITHUB_API = "https://api.github.com"
    MAX_FILES = 3
    MAX_FILE_CHARS = 4000
    MAX_TOTAL_CHARS = 8000

    PRIORITY_NAMES = (
        "auth", "login", "user", "route", "api",
        "database", "db", "security", "config",
        "payment", "admin", "permission", "token",
    )

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _priority(self, item: dict) -> tuple:
        name = str(item.get("filename", "")).lower()
        priority = any(word in name for word in self.PRIORITY_NAMES)
        changes = int(item.get("changes") or 0)
        return (not priority, -changes, name)

    def _extract_patch(self, patch: str) -> tuple[int, str]:
        output = []
        new_line = 1
        start_line = 1
        found_hunk = False

        for line in patch.splitlines():
            match = re.match(
                r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@",
                line,
            )

            if match:
                if found_hunk:
                    break
                start_line = int(match.group(1))
                new_line = start_line
                found_hunk = True
                continue

            if not found_hunk:
                continue

            if line.startswith("\\"):
                continue

            if line.startswith("+"):
                output.append(line[1:])
                new_line += 1
            elif line.startswith("-"):
                continue
            elif line.startswith(" "):
                output.append(line[1:])
                new_line += 1

        return start_line, "\n".join(output).strip()

    async def analyze(
        self,
        full_name: str,
        token: str,
        branch_a: str,
        branch_b: str,
    ):
        if branch_a.strip() == branch_b.strip():
            raise MergeIntelligenceError(
                "Choose two different branches to compare."
            )

        base = quote(branch_a.strip(), safe="")
        head = quote(branch_b.strip(), safe="")
        url = (
            f"{self.GITHUB_API}/repos/{full_name}/compare/"
            f"{base}...{head}"
        )

        try:
            async with httpx.AsyncClient(timeout=25) as client:
                response = await client.get(
                    url,
                    headers=self._headers(token),
                )

            if response.status_code == 404:
                raise MergeIntelligenceError(
                    "GitHub could not find one of the branches."
                )
            if response.status_code == 401:
                raise MergeIntelligenceError(
                    "GitHub rejected the access token. Reconnect GitHub."
                )
            if response.status_code == 403:
                raise MergeIntelligenceError(
                    "GitHub denied access or the API rate limit was reached."
                )
            if response.status_code >= 400:
                raise MergeIntelligenceError(
                    f"GitHub comparison failed ({response.status_code})."
                )

            comparison = response.json()

        except httpx.TimeoutException as exc:
            raise MergeIntelligenceError(
                "GitHub comparison timed out. Try again."
            ) from exc
        except httpx.RequestError as exc:
            raise MergeIntelligenceError(
                "Unable to connect to GitHub."
            ) from exc

        changed = comparison.get("files") or []
        limitations = []
        candidates = []

        for item in sorted(changed, key=self._priority):
            if len(candidates) >= self.MAX_FILES:
                break

            if item.get("status") == "removed":
                continue

            patch = item.get("patch")
            path = item.get("filename")

            if not patch or not path:
                limitations.append(
                    f"Skipped {path or 'an unnamed file'} because GitHub "
                    "did not provide a text diff."
                )
                continue

            start_line, content = self._extract_patch(patch)

            if not content:
                continue

            content = content[:self.MAX_FILE_CHARS]

            current_size = sum(
                len(file.content) for file in candidates
            )

            remaining = self.MAX_TOTAL_CHARS - current_size
            if remaining <= 0:
                break

            content = content[:remaining]

            try:
                candidates.append(
                    CodeFileInput(
                        path=path,
                        content=content,
                        start_line=max(start_line, 1),
                    )
                )
            except Exception:
                limitations.append(
                    f"Skipped {path} because its diff could not be validated."
                )

        if not candidates:
            return {
                "repository": full_name,
                "branch_a": branch_a,
                "branch_b": branch_b,
                "comparison_status": comparison.get("status", "unknown"),
                "ahead_by": comparison.get("ahead_by", 0),
                "behind_by": comparison.get("behind_by", 0),
                "changed_files": len(changed),
                "files_analyzed": 0,
                "summary": (
                    "No analyzable text changes were found between "
                    "these branches."
                ),
                "findings": [],
                "limitations": list(dict.fromkeys(limitations)),
            }

        if len(changed) > len(candidates):
            limitations.append(
                f"Analyzed {len(candidates)} files within the resource limit; "
                f"{len(changed) - len(candidates)} changed files were not analyzed."
            )

        try:
            analysis = await security_analysis_service.analyze(
                SecurityAnalysisRequest(
                    files=candidates,
                    research_query=(
                        "Security risks in changed code during Git branch "
                        "integration, including authorization, injection, "
                        "secrets, input validation and unsafe data handling."
                    ),
                )
            )
        except SecurityAnalysisError as exc:
            raise MergeIntelligenceError(
                "AI security analysis failed. Check the configured AI provider."
            ) from exc

        limitations.extend(analysis.limitations)

        return {
            "repository": full_name,
            "branch_a": branch_a,
            "branch_b": branch_b,
            "comparison_status": comparison.get("status", "unknown"),
            "ahead_by": comparison.get("ahead_by", 0),
            "behind_by": comparison.get("behind_by", 0),
            "changed_files": len(changed),
            "files_analyzed": len(candidates),
            "summary": analysis.summary,
            "findings": analysis.findings,
            "limitations": list(dict.fromkeys(limitations))[:30],
        }


merge_intelligence_service = MergeIntelligenceService()