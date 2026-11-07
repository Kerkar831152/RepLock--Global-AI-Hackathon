
import asyncio
import json
import tempfile
from pathlib import Path, PurePosixPath

from app.core.config import settings


class SemgrepError(Exception):
    pass


class SemgrepService:

    SEVERITY_MAP = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low"
    }

    MAX_OUTPUT_SIZE = 5 * 1024 * 1024
    MAX_FINDINGS = 1000

    async def scan(self, repository_path: str) -> dict:
        executable = Path(settings.SEMGREP_PATH).resolve()
        root = Path(repository_path).resolve()

        if not executable.is_file():
            raise SemgrepError(
                "Semgrep executable not found. Check SEMGREP_PATH."
            )

        if not root.is_dir():
            raise SemgrepError(
                "Repository directory does not exist"
            )

        command = [
            str(executable),
            "scan",
            "--config", "auto",
            "--json",
            "--quiet",
            "--metrics=off",
            "--no-git-ignore",
            "--jobs", "1",
            "--timeout", "10",
            str(root)
        ]

        process = None

        try:
            with tempfile.TemporaryFile(mode="w+b") as stdout_file:
                with tempfile.TemporaryFile(mode="w+b") as stderr_file:
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        cwd=str(root),
                        stdout=stdout_file,
                        stderr=stderr_file
                    )

                    try:
                        await asyncio.wait_for(
                            process.wait(),
                            timeout=settings.SEMGREP_TIMEOUT
                        )

                    except asyncio.TimeoutError as exc:
                        process.kill()
                        await process.wait()

                        raise SemgrepError(
                            "Semgrep scan exceeded its time limit"
                        ) from exc

                    stdout_file.seek(0, 2)
                    output_size = stdout_file.tell()

                    if output_size > self.MAX_OUTPUT_SIZE:
                        raise SemgrepError(
                            "Semgrep output exceeded the allowed size"
                        )

                    stdout_file.seek(0)
                    output = stdout_file.read()

                    stderr_file.seek(0)
                    error_output = stderr_file.read(500).decode(
                        "utf-8",
                        errors="replace"
                    )

        except SemgrepError:
            raise

        except OSError as exc:
            if process and process.returncode is None:
                process.kill()
                await process.wait()

            raise SemgrepError(
                "Unable to execute Semgrep"
            ) from exc

        if process.returncode not in (0, 1):
            raise SemgrepError(
                "Semgrep execution failed: "
                + error_output[:300]
            )

        try:
            data = json.loads(output.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SemgrepError(
                "Semgrep returned invalid JSON"
            ) from exc

        findings = []

        for item in data.get("results", [])[:self.MAX_FINDINGS]:
            extra = item.get("extra") or {}
            metadata = extra.get("metadata") or {}
            start = item.get("start") or {}

            raw_path = str(item.get("path") or "").replace("\\", "/")
            root_path = root.as_posix().rstrip("/")
            root_lower = root_path.casefold()
            raw_lower = raw_path.casefold()

            if raw_lower == root_lower:
                continue

            if raw_lower.startswith(root_lower + "/"):
                raw_path = raw_path[len(root_path) + 1:]

            relative_path = PurePosixPath(raw_path)

            if relative_path.is_absolute() or ".." in relative_path.parts:
                continue

            normalized_path = relative_path.as_posix().removeprefix("./")

            if not normalized_path or normalized_path == ".":
                continue

            severity = self.SEVERITY_MAP.get(
                str(extra.get("severity", "WARNING")).upper(),
                "medium"
            )

            line_number = start.get("line", 1)

            if not isinstance(line_number, int) or line_number < 1:
                line_number = 1

            findings.append({
                "title": str(
                    extra.get("message")
                    or item.get("check_id")
                    or "Security issue"
                )[:200],
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
                "evidence": str(extra.get("lines") or "")[:1000]
            })

        return {
            "findings": findings,
            "total_findings": len(data.get("results", [])),
            "errors": data.get("errors", [])
        }


semgrep_service = SemgrepService()
