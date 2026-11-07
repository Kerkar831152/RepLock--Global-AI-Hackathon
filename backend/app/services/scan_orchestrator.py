
import os
import tempfile
from pathlib import Path

from app.core.config import settings
from app.schemas.security_analysis import (
    SecurityAnalysisRequest,
    CodeFileInput,
    ScannerSignalInput
)
from app.services.repository_download_service import (
    repository_download_service,
    RepositoryDownloadError
)
from app.services.semgrep_service import (
    semgrep_service,
    SemgrepError
)
from app.services.security_analysis_service import (
    security_analysis_service,
    SecurityAnalysisError
)


class ScanOrchestrationError(Exception):
    pass


class ScanOrchestrator:

    MAX_AI_FILES = 3
    MAX_AI_FILE_CHARS = 4000
    MAX_AI_TOTAL_CHARS = 8000
    MAX_SCANNER_SIGNALS = 5

    MAX_SOURCE_FILES = 200
    MAX_SOURCE_TOTAL_SIZE = 5 * 1024 * 1024

    PRIORITY_NAMES = (
        "auth", "login", "user", "route", "api",
        "database", "db", "security", "config",
        "payment", "admin"
    )

    IGNORED_DIRS = {
        ".git", ".venv", "venv", "env",
        "node_modules", "__pycache__", "dist",
        "build", "coverage", ".next", "vendor",
        "target", "replock_env", "semgrep_env"
    }

    IGNORED_SUFFIXES = {
        ".pem", ".key", ".p12", ".pfx",
        ".crt", ".cer", ".der"
    }

    SENSITIVE_NAMES = {
        ".env", ".env.local", ".env.production",
        ".env.development", "credentials.json",
        "secrets.json", "secrets.yaml", "secrets.yml",
        "service-account.json", "id_rsa", "id_ed25519",
        "private_key", "privatekey"
    }

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4
    }

    async def run(self, repository, access_token: str) -> dict:
        with tempfile.TemporaryDirectory(prefix="replock_") as temp:
            repository_path = Path(temp) / "source"

            try:
                commit_sha = await repository_download_service.download(
                    repository,
                    access_token,
                    repository_path
                )
            except RepositoryDownloadError as exc:
                raise ScanOrchestrationError(str(exc)) from exc
            except Exception as exc:
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
                raise ScanOrchestrationError(
                    "Security scanner failed unexpectedly"
                ) from exc

            source_files = self._read_source_files(repository_path)

            if not source_files:
                raise ScanOrchestrationError(
                    "No readable source files were available for AI analysis"
                )

            selected_files = self._select_files(
                source_files,
                scanner_result["findings"]
            )

            if not selected_files:
                raise ScanOrchestrationError(
                    "Unable to select source code for AI analysis"
                )

            scanner_signals = self._select_signals(
                scanner_result["findings"],
                selected_files
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
                        start_line=item["start_line"]
                    )
                    for item in selected_files
                ],
                scanner_findings=[
                    ScannerSignalInput(**item)
                    for item in scanner_signals
                ],
                research_query=research_query
            )

            try:
                analysis = await security_analysis_service.analyze(request)
            except SecurityAnalysisError as exc:
                raise ScanOrchestrationError(
                    "AI security analysis could not be completed"
                ) from exc
            except Exception as exc:
                raise ScanOrchestrationError(
                    "AI security analysis failed unexpectedly"
                ) from exc

            summary = (
                f"{analysis.summary}\n\n"
                f"Semgrep detected {scanner_result['total_findings']} "
                f"potential issue(s). "
                f"AI validated {len(analysis.findings)} finding(s)."
            )

            if scanner_result.get("errors"):
                summary += (
                    f" Semgrep reported {len(scanner_result['errors'])} "
                    "scanner warning(s)."
                )

            if len(scanner_signals) < scanner_result["total_findings"]:
                analysis.limitations.append(
                    "Only a limited selection of Semgrep findings and "
                    "source-code context was submitted for AI validation."
                )

            return {
                "commit_sha": commit_sha,
                "summary": summary[:5000],
                "findings": analysis.findings,
                "limitations": list(dict.fromkeys(analysis.limitations)),
                "semgrep_findings": scanner_result["total_findings"],
                "files_analyzed": len(source_files)
            }

    def _read_source_files(self, root: Path) -> list[dict]:
        files = []
        total_size = 0
        root = root.resolve()

        for current_dir, directories, filenames in os.walk(
            root,
            topdown=True,
            followlinks=False
        ):
            current_path = Path(current_dir)

            directories[:] = [
                name for name in directories
                if name not in self.IGNORED_DIRS
                and not (current_path / name).is_symlink()
            ]

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

                if len(files) >= self.MAX_SOURCE_FILES:
                    return files

                try:
                    resolved = path.resolve()
                    resolved.relative_to(root)

                    size = resolved.stat().st_size

                    if (
                        size <= 0
                        or size > settings.REPOSITORY_MAX_FILE_SIZE
                    ):
                        continue

                    if total_size + size > self.MAX_SOURCE_TOTAL_SIZE:
                        return files

                    content = resolved.read_text(
                        encoding="utf-8",
                        errors="replace"
                    )

                    if "\x00" in content:
                        continue

                    files.append({
                        "path": resolved.relative_to(root).as_posix(),
                        "content": content
                    })

                    total_size += size

                except (OSError, ValueError):
                    continue

        return files

    def _select_files(
        self,
        files: list[dict],
        scanner_findings: list[dict]
    ) -> list[dict]:
        by_path = {
            item["path"]: item for item in files
        }

        finding_groups = {}

        for finding in scanner_findings:
            path = Path(finding["file_path"]).as_posix()

            if path in by_path:
                finding_groups.setdefault(path, []).append(finding)

        def priority(item):
            path = item["path"].lower()
            findings = finding_groups.get(item["path"], [])

            severity = min(
                (
                    self.SEVERITY_ORDER.get(
                        finding["severity"], 4
                    )
                    for finding in findings
                ),
                default=5
            )

            name_score = sum(
                1 for word in self.PRIORITY_NAMES
                if word in path
            )

            return (
                severity,
                -len(findings),
                -name_score,
                len(item["content"])
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
                        self.SEVERITY_ORDER.get(
                            finding["severity"], 4
                        ),
                        finding.get("line_number", 1)
                    )
                )

                target_line = best_finding.get("line_number", 1)

            context = self._build_context(
                item["content"],
                target_line
            )

            if not context:
                continue

            content, start_line = context

            if total_chars + len(content) > self.MAX_AI_TOTAL_CHARS:
                continue

            selected.append({
                "path": item["path"],
                "content": content,
                "start_line": start_line
            })

            total_chars += len(content)

            if len(selected) >= self.MAX_AI_FILES:
                break

        return selected

    def _build_context(
        self,
        content: str,
        target_line: int
    ) -> tuple[str, int] | None:
        lines = content.splitlines()

        if not lines:
            return None

        target_line = max(1, min(target_line, len(lines)))

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
        selected_files: list[dict]
    ) -> list[dict]:
        selected_ranges = {
            item["path"]: (
                item["start_line"],
                item["start_line"] + len(item["content"].splitlines()) - 1
            )
            for item in selected_files
        }

        relevant = []

        for item in findings:
            path = Path(item["file_path"]).as_posix()

            if path not in selected_ranges:
                continue

            start, end = selected_ranges[path]
            line = item.get("line_number", 1)

            if not start <= line <= end:
                continue

            relevant.append(item)

        relevant.sort(
            key=lambda item: (
                self.SEVERITY_ORDER.get(item["severity"], 4),
                item.get("line_number", 1)
            )
        )

        return [
            {
                "title": item["title"],
                "description": (
                    f"Line {item.get('line_number', 1)}: "
                    f"{item['description']}"
                )[:1000],
                "severity": item["severity"],
                "file_path": item["file_path"]
            }
            for item in relevant[:self.MAX_SCANNER_SIGNALS]
        ]


scan_orchestrator = ScanOrchestrator()
