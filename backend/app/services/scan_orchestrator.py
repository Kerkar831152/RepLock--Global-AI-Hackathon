
import asyncio
import logging
import os
import tempfile
from pathlib import Path

from app.core.config import settings
from app.schemas.security_analysis import (
    SecurityAnalysisRequest,
    CodeFileInput,
    ScannerSignalInput,
)
from app.services.repository_download_service import (
    repository_download_service,
    RepositoryDownloadError,
)
from app.services.semgrep_service import (
    semgrep_service,
    SemgrepError,
)
from app.services.security_analysis_service import (
    security_analysis_service,
    SecurityAnalysisError,
)


class ScanOrchestrationError(Exception):
    pass


logger = logging.getLogger(__name__)


class ScanOrchestrator:
    MAX_CONCURRENT_SCANS = 1
    MAX_AI_FILES = 3
    MAX_AI_FILE_CHARS = 4000
    MAX_AI_TOTAL_CHARS = 8000
    MAX_SCANNER_SIGNALS = 5

    PRIORITY_NAMES = (
        "auth", "login", "user", "route", "api",
        "database", "db", "security", "config",
        "payment", "admin",
    )

    IGNORED_DIRS = {
        ".git", ".venv", "venv", "env",
        "node_modules", "__pycache__", "dist",
        "build", "coverage", ".next", "vendor",
        "target", "replock_env", "semgrep_env",
    }

    IGNORED_SUFFIXES = {
        ".pem", ".key", ".p12", ".pfx",
        ".crt", ".cer", ".der",
    }

    SENSITIVE_NAMES = {
        ".env", ".env.local", ".env.production",
        ".env.development", "credentials.json",
        "secrets.json", "secrets.yaml", "secrets.yml",
        "service-account.json", "id_rsa", "id_ed25519",
        "private_key", "privatekey",
    }

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def __init__(self):
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_SCANS)

    def _normalize_repo_path(self, value: str) -> str | None:
        if not isinstance(value, str):
            return None

        value = value.strip().replace("\\", "/")

        if (
            not value
            or value.startswith("/")
            or "\x00" in value
            or ":" in value.split("/")[0]
        ):
            return None

        parts = value.split("/")

        if any(part in {"", ".", ".."} for part in parts):
            return None

        return "/".join(parts)

    def _severity_rank(self, value) -> int:
        if not isinstance(value, str):
            return 4

        return self.SEVERITY_ORDER.get(value.lower(), 4)

    async def run(self, repository, access_token: str) -> dict:
        async with self._semaphore:
            return await self._run(repository, access_token)

    async def _run(self, repository, access_token: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="replock_") as temp:
            repository_path = Path(temp) / "source"

            try:
                commit_sha = await repository_download_service.download(
                    repository,
                    access_token,
                    repository_path,
                )
            except RepositoryDownloadError as exc:
                raise ScanOrchestrationError(str(exc)) from exc
            except Exception as exc:
                logger.exception("Repository download failed unexpectedly")
                raise ScanOrchestrationError(
                    "Repository download failed unexpectedly"
                ) from exc

            try:
                scanner_result = await semgrep_service.scan(
                    str(repository_path)
                )
            except SemgrepError as exc:
                raise ScanOrchestrationError(str(exc)) from exc
            except Exception as exc:
                logger.exception("Security scanner failed unexpectedly")
                raise ScanOrchestrationError(
                    "Security scanner failed unexpectedly"
                ) from exc

            if not isinstance(scanner_result, dict):
                raise ScanOrchestrationError(
                    "Security scanner returned an invalid result"
                )

            scanner_findings = scanner_result.get("findings", [])

            if not isinstance(scanner_findings, list):
                raise ScanOrchestrationError(
                    "Security scanner returned invalid findings"
                )

            source_files, source_limitations = self._read_source_files(
                repository_path
            )

            if not source_files:
                raise ScanOrchestrationError(
                    "No readable source files were available for AI analysis"
                )

            selected_files = self._select_files(
                source_files,
                scanner_findings,
            )

            if not selected_files:
                raise ScanOrchestrationError(
                    "Unable to select source code for AI analysis"
                )

            scanner_signals = self._select_signals(
                scanner_findings,
                selected_files,
            )

            research_query = None

            if scanner_signals:
                categories = list(dict.fromkeys(
                    item["title"][:80]
                    for item in scanner_signals[:2]
                ))

                research_query = (
                    "Secure coding guidance and remediation for: "
                    + "; ".join(categories)
                )

            request = SecurityAnalysisRequest(
                files=[
                    CodeFileInput(
                        path=item["path"],
                        content=item["content"],
                        start_line=item["start_line"],
                        original_line_count=item["original_line_count"],
                    )
                    for item in selected_files
                ],
                scanner_findings=[
                    ScannerSignalInput(**item)
                    for item in scanner_signals
                ],
                research_query=research_query,
            )

            try:
                analysis = await security_analysis_service.analyze(request)
            except SecurityAnalysisError as exc:
                raise ScanOrchestrationError(
                    "AI security analysis could not be completed"
                ) from exc
            except Exception as exc:
                logger.exception("AI security analysis failed unexpectedly")
                raise ScanOrchestrationError(
                    "AI security analysis failed unexpectedly"
                ) from exc

            total_findings = scanner_result.get("total_findings", 0)

            try:
                total_findings = max(0, int(total_findings))
            except (TypeError, ValueError):
                total_findings = len(scanner_findings)

            summary = (
                f"{analysis.summary}\n\n"
                f"Semgrep detected {total_findings} "
                f"potential issue(s). "
                f"AI validated {len(analysis.findings)} finding(s)."
            )

            scanner_errors = scanner_result.get("errors", [])

            if isinstance(scanner_errors, list) and scanner_errors:
                summary += (
                    f" Semgrep reported {len(scanner_errors)} "
                    "scanner warning(s)."
                )

            limitations = list(analysis.limitations)
            limitations.extend(source_limitations)

            if total_findings == 0:
                limitations.append(
                    "Semgrep detected no findings; this does not establish "
                    "that the repository is free of vulnerabilities."
                )

            if isinstance(scanner_errors, list) and scanner_errors:
                limitations.append(
                    "Semgrep reported scanner warnings; its results may be "
                    "incomplete."
                )

            if len(scanner_signals) < total_findings:
                limitations.append(
                    "Only a limited selection of Semgrep findings and "
                    "source-code context was submitted for AI validation."
                )

            if len(selected_files) < len(source_files):
                limitations.append(
                    "Only a subset of readable source files was submitted "
                    "for AI analysis because of context and resource limits."
                )

            return {
                "commit_sha": commit_sha,
                "summary": summary[:5000],
                "findings": analysis.findings,
                "limitations": list(dict.fromkeys(limitations))[:30],
                "semgrep_findings": total_findings,
                "files_analyzed": len(source_files),
            }

    def _read_source_files(
        self,
        root: Path,
    ) -> tuple[list[dict], list[str]]:
        files = []
        limitations = []
        total_size = 0
        root = root.resolve()

        max_files = settings.REPOSITORY_MAX_FILES
        max_total_size = settings.REPOSITORY_MAX_TOTAL_SIZE
        max_file_size = settings.REPOSITORY_MAX_FILE_SIZE

        for current_dir, directories, filenames in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current_dir)

            directories[:] = sorted(
                name for name in directories
                if name not in self.IGNORED_DIRS
                and not (current_path / name).is_symlink()
            )

            for filename in sorted(filenames):
                path = current_path / filename
                lower_name = filename.lower()

                if path.is_symlink():
                    continue

                if (
                    lower_name.startswith(".env")
                    or lower_name in self.SENSITIVE_NAMES
                    or path.suffix.lower() in self.IGNORED_SUFFIXES
                ):
                    continue

                if len(files) >= max_files:
                    limitations.append(
                        f"Source-file inspection stopped at the "
                        f"{max_files}-file limit."
                    )
                    return files, limitations

                try:
                    resolved = path.resolve()
                    resolved.relative_to(root)

                    size = resolved.stat().st_size

                    if size <= 0 or size > max_file_size:
                        continue

                    if total_size + size > max_total_size:
                        limitations.append(
                            "Source-file inspection stopped at the "
                            f"{max_total_size // (1024 * 1024)} MB "
                            "total source-size limit."
                        )
                        return files, limitations

                    content = resolved.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )

                    if "\x00" in content:
                        continue

                    files.append({
                        "path": resolved.relative_to(root).as_posix(),
                        "content": content,
                    })

                    total_size += size

                except (OSError, ValueError):
                    continue

        return files, limitations

    def _select_files(
        self,
        files: list[dict],
        scanner_findings: list[dict],
    ) -> list[dict]:
        by_path = {
            item["path"]: item for item in files
        }

        finding_groups = {}

        for finding in scanner_findings:
            if not isinstance(finding, dict):
                continue

            path = self._normalize_repo_path(
                finding.get("file_path")
            )

            if path and path in by_path:
                finding_groups.setdefault(path, []).append(finding)

        def priority(item):
            path = item["path"].lower()
            findings = finding_groups.get(item["path"], [])

            severity = min(
                (
                    self._severity_rank(finding.get("severity"))
                    for finding in findings
                ),
                default=5,
            )

            name_score = sum(
                1 for word in self.PRIORITY_NAMES
                if word in path
            )

            return (
                severity,
                -len(findings),
                -name_score,
                len(item["content"]),
            )

        ordered = sorted(files, key=priority)

        selected = []
        total_chars = 0

        for item in ordered:
            findings = finding_groups.get(item["path"], [])
            target_line = 1

            if findings:
                best_finding = min(
                    findings,
                    key=lambda finding: (
                        self._severity_rank(
                            finding.get("severity")
                        ),
                        self._safe_line_number(
                            finding.get("line_number")
                        ),
                    ),
                )

                target_line = self._safe_line_number(
                    best_finding.get("line_number")
                )

            context = self._build_context(
                item["content"],
                target_line,
            )

            if not context:
                continue

            content, start_line = context

            if total_chars + len(content) > self.MAX_AI_TOTAL_CHARS:
                continue

            selected.append({
                "path": item["path"],
                "content": content,
                "start_line": start_line,
                "original_line_count": len(
                    item["content"].splitlines()
                ),
            })

            total_chars += len(content)

            if len(selected) >= self.MAX_AI_FILES:
                break

        return selected

    @staticmethod
    def _safe_line_number(value) -> int:
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            return 1

    def _build_context(
        self,
        content: str,
        target_line: int,
    ) -> tuple[str, int] | None:
        lines = content.splitlines()

        if not lines:
            return None

        if len(content) <= self.MAX_AI_FILE_CHARS:
            if content.strip():
                return content, 1

            return None

        target_line = self._safe_line_number(target_line)
        target_line = min(target_line, len(lines))

        start = max(1, target_line - 25)
        end = min(len(lines), target_line + 35)

        while start <= end:
            selected_lines = lines[start - 1:end]
            snippet = "\n".join(selected_lines)

            if len(snippet) <= self.MAX_AI_FILE_CHARS:
                if snippet.strip():
                    return snippet, start

                return None

            before = target_line - start
            after = end - target_line

            if before > after:
                start += 1
            else:
                end -= 1

        return None

    def _select_signals(
        self,
        findings: list[dict],
        selected_files: list[dict],
    ) -> list[dict]:
        selected_ranges = {
            item["path"]: (
                item["start_line"],
                item["start_line"]
                + len(item["content"].splitlines()) - 1,
            )
            for item in selected_files
        }

        relevant = []

        for item in findings:
            if not isinstance(item, dict):
                continue

            path = self._normalize_repo_path(
                item.get("file_path")
            )

            if path not in selected_ranges:
                continue

            start, end = selected_ranges[path]
            line = self._safe_line_number(item.get("line_number"))

            if not start <= line <= end:
                continue

            relevant.append((item, path, line))

        relevant.sort(
            key=lambda entry: (
                self._severity_rank(entry[0].get("severity")),
                entry[2],
            )
        )

        signals = []

        for item, path, line in relevant[:self.MAX_SCANNER_SIGNALS]:
            severity = item.get("severity")

            if not isinstance(severity, str):
                severity = None
            elif severity.lower() not in self.SEVERITY_ORDER:
                severity = None
            else:
                severity = severity.lower()

            signals.append({
                "title": str(
                    item.get("title") or "Potential security issue"
                )[:200],
                "description": (
                    f"Line {line}: "
                    f"{item.get('description') or 'Scanner detected a potential issue.'}"
                )[:1000],
                "severity": severity,
                "file_path": path,
            })

        return signals


scan_orchestrator = ScanOrchestrator()
