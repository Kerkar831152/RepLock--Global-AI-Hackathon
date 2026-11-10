
import asyncio
import json
import tempfile
from pathlib import Path, PurePosixPath

from app.core.config import settings


class SemgrepError(Exception):
    pass


class SemgrepService:
    SCAN_CONFIG = "p/security-audit"
    MAX_CONCURRENT_SCANS = 1

    SEVERITY_MAP = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }

    MAX_OUTPUT_SIZE = 5 * 1024 * 1024
    MAX_FINDINGS = 1000

    def __init__(self):
        self._semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_SCANS)

    async def _stop_process(self, process):
        if process and process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass

            await process.wait()

    def _normalize_path(self, raw_path: str, root: Path) -> str | None:
        if not raw_path:
            return None

        raw_path = raw_path.replace("\\", "/")
        path = PurePosixPath(raw_path)

        if path.is_absolute():
            try:
                resolved = Path(raw_path).resolve()
                relative = resolved.relative_to(root)
            except (OSError, ValueError):
                return None

            normalized = relative.as_posix()
        else:
            if ".." in path.parts:
                return None

            normalized = path.as_posix().removeprefix("./")

        if not normalized or normalized == ".":
            return None

        return normalized

    def _build_command(self, executable: Path, root: Path) -> list[str]:
        return [
            str(executable),
            "scan",
            "--config", self.SCAN_CONFIG,
            "--json",
            "--quiet",
            "--metrics=off",
            "--no-git-ignore",
            "--jobs", "1",
            "--timeout", "10",
            str(root),
        ]

    async def scan(self, repository_path: str) -> dict:
        async with self._semaphore:
            return await self._scan(repository_path)

    async def _scan(self, repository_path: str) -> dict:
        executable = Path(settings.SEMGREP_PATH).resolve()
        root = Path(repository_path).resolve()

        if not executable.is_file():
            raise SemgrepError(
                "Semgrep executable not found. Check SEMGREP_PATH."
            )

        if not root.is_dir():
            raise SemgrepError(
                "Repository directory does not exist."
            )

        command = self._build_command(executable, root)

        process = None

        try:
            with tempfile.TemporaryFile(mode="w+b") as stdout_file:
                with tempfile.TemporaryFile(mode="w+b") as stderr_file:
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        cwd=str(root),
                        stdout=stdout_file,
                        stderr=stderr_file,
                    )

                    try:
                        await asyncio.wait_for(
                            process.wait(),
                            timeout=settings.SEMGREP_TIMEOUT,
                        )
                    except asyncio.TimeoutError as exc:
                        await self._stop_process(process)
                        raise SemgrepError(
                            "Semgrep scan exceeded its time limit."
                        ) from exc

                    stdout_file.seek(0, 2)
                    output_size = stdout_file.tell()

                    if output_size > self.MAX_OUTPUT_SIZE:
                        raise SemgrepError(
                            "Semgrep output exceeded the allowed size."
                        )

                    stdout_file.seek(0)
                    output = stdout_file.read()

                    stderr_file.seek(0)
                    error_output = stderr_file.read(500).decode(
                        "utf-8",
                        errors="replace",
                    )

        except SemgrepError:
            raise

        except asyncio.CancelledError:
            await self._stop_process(process)
            raise

        except OSError as exc:
            await self._stop_process(process)
            raise SemgrepError(
                "Unable to execute Semgrep."
            ) from exc

        if process.returncode not in (0, 1):
            raise SemgrepError(
                "Semgrep execution failed: " + error_output[:300]
            )

        return self._parse_output(output, root)

    def _parse_output(self, output: bytes, root: Path) -> dict:
        try:
            data = json.loads(output.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SemgrepError(
                "Semgrep returned invalid JSON."
            ) from exc

        if not isinstance(data, dict):
            raise SemgrepError(
                "Semgrep returned an invalid response."
            )

        results = data.get("results")

        if not isinstance(results, list):
            raise SemgrepError(
                "Semgrep returned an invalid findings list."
            )

        errors = data.get("errors", [])

        if not isinstance(errors, list):
            raise SemgrepError(
                "Semgrep returned an invalid errors list."
            )

        findings = []
        if len(results) > self.MAX_FINDINGS:
            errors.append(
                "Semgrep findings were truncated at the configured limit."
            )

        for item in results[:self.MAX_FINDINGS]:
            if not isinstance(item, dict):
                errors.append("Semgrep returned a malformed finding.")
                continue

            extra = item.get("extra")

            if not isinstance(extra, dict):
                errors.append("Semgrep returned a finding with invalid metadata.")
                continue

            metadata = extra.get("metadata") or {}

            if not isinstance(metadata, dict):
                metadata = {}

            start = item.get("start")

            if not isinstance(start, dict):
                errors.append("Semgrep returned a finding with an invalid location.")
                continue

            line_number = start.get("line")
            if (
                not isinstance(line_number, int)
                or isinstance(line_number, bool)
                or line_number < 1
            ):
                errors.append("Semgrep returned a finding with an invalid line.")
                continue

            normalized_path = self._normalize_path(
                str(item.get("path") or ""),
                root,
            )

            if not normalized_path:
                errors.append("Semgrep returned a finding with an invalid path.")
                continue

            severity = self.SEVERITY_MAP.get(
                str(extra.get("severity", "WARNING")).upper(),
                "medium",
            )

            message = str(
                extra.get("message")
                or item.get("check_id")
                or "Security issue"
            )

            findings.append({
                "title": message[:200],
                "description": str(
                    extra.get("message")
                    or "Semgrep detected a potential security issue."
                )[:1000],
                "severity": severity,
                "file_path": normalized_path,
                "line_number": line_number,
                "rule_id": str(item.get("check_id") or "")[:300],
                "cwe": metadata.get("cwe"),
                "confidence": metadata.get("confidence"),
                "evidence": str(extra.get("lines") or "")[:1000],
            })

        return {
            "findings": findings,
            "total_findings": len(results),
            "errors": errors,
        }


semgrep_service = SemgrepService()
