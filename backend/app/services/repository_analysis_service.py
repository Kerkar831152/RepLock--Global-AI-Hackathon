
import os
from pathlib import Path

from tree_sitter_language_pack import detect_language_from_path

from app.services.code_intelligence_service import (
    code_intelligence_service,
    CodeIntelligenceError,
)


class RepositoryAnalysisError(Exception):
    pass


class RepositoryAnalysisService:
    MAX_FILES = 200
    MAX_TOTAL_SIZE = 5 * 1024 * 1024
    MAX_FILE_SIZE = 200_000

    IGNORED_DIRS = {
        ".git",
        ".venv",
        "venv",
        "env",
        "replock_env",
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        "dist",
        "build",
        "coverage",
        ".next",
        ".nuxt",
        "vendor",
        "target",
    }

    IGNORED_FILES = {
        ".env",
        ".env.local",
        ".env.production",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
    }

    SENSITIVE_SUFFIXES = {
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".crt",
        ".cer",
        ".der",
    }

    def analyze_repository(self, repository_path: str) -> dict:
        root = Path(repository_path).resolve()

        if not root.exists() or not root.is_dir():
            raise RepositoryAnalysisError(
                "Repository directory does not exist"
            )

        files = []
        skipped_files = 0
        total_size = 0
        truncated = False
        language_counts = {}

        for current_dir, directories, filenames in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            current_path = Path(current_dir)

            directories[:] = [
                directory
                for directory in directories
                if directory not in self.IGNORED_DIRS
                and not (current_path / directory).is_symlink()
            ]

            for filename in sorted(filenames):
                file_path = current_path / filename

                if file_path.is_symlink():
                    skipped_files += 1
                    continue

                if filename in self.IGNORED_FILES:
                    skipped_files += 1
                    continue

                if filename.startswith(".env"):
                    skipped_files += 1
                    continue

                if file_path.suffix.lower() in self.SENSITIVE_SUFFIXES:
                    skipped_files += 1
                    continue

                language = detect_language_from_path(str(file_path))

                if language is None:
                    skipped_files += 1
                    continue

                if len(files) >= self.MAX_FILES:
                    truncated = True
                    break

                try:
                    file_size = file_path.stat().st_size

                    if file_size == 0 or file_size > self.MAX_FILE_SIZE:
                        skipped_files += 1
                        continue

                    if total_size + file_size > self.MAX_TOTAL_SIZE:
                        truncated = True
                        break

                    content = file_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )

                    if "\x00" in content:
                        skipped_files += 1
                        continue

                    result = code_intelligence_service.analyze_file(
                        file_path.relative_to(root).as_posix(),
                        content,
                    )

                    files.append(result)
                    total_size += file_size

                    language_counts[language] = (
                        language_counts.get(language, 0) + 1
                    )

                except (OSError, CodeIntelligenceError):
                    skipped_files += 1
                    continue

            if truncated:
                break

        total_functions = sum(
            len(file["functions"]) for file in files
        )

        total_classes = sum(
            len(file["classes"]) for file in files
        )

        total_imports = sum(
            len(file["imports"]) for file in files
        )

        return {
            "repository": root.name,
            "files_analyzed": len(files),
            "files_skipped": skipped_files,
            "total_size_bytes": total_size,
            "language_counts": language_counts,
            "total_functions": total_functions,
            "total_classes": total_classes,
            "total_imports": total_imports,
            "truncated": truncated,
            "files": files,
        }


repository_analysis_service = RepositoryAnalysisService()
