
import asyncio
import os
import tempfile
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import quote

import httpx

from app.core.config import settings


class RepositoryDownloadError(Exception):
    pass


class RepositoryDownloadService:
    GITHUB_API = "https://api.github.com"

    ALLOWED_SUFFIXES = {
        ".py", ".js", ".jsx", ".ts", ".tsx",
        ".java", ".kt", ".go", ".rs", ".php",
        ".rb", ".cs", ".c", ".cpp", ".h", ".hpp",
        ".swift", ".dart", ".sql", ".html", ".css",
        ".vue", ".svelte", ".sh", ".yaml", ".yml",
        ".json", ".toml", ".ini", ".xml", ".conf",
        ".properties",
    }

    ALLOWED_NAMES = {
        "Dockerfile",
        "Makefile",
        "requirements.txt",
        "pyproject.toml",
        "package.json",
        "composer.json",
        "Gemfile",
        "go.mod",
        "Cargo.toml",
    }

    IGNORED_DIRS = {
        ".git", "node_modules", "vendor", "dist",
        "build", ".venv", "venv", "__pycache__",
        "coverage", ".next", "target",
    }

    async def download(
        self,
        repository,
        access_token: str,
        destination: Path,
    ) -> str:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        full_name = quote(repository.full_name, safe="/")
        branch = quote(repository.default_branch, safe="")

        timeout = httpx.Timeout(60, connect=10)
        archive_fd, archive_name = tempfile.mkstemp(
            prefix="replock_archive_",
            suffix=".tar.gz",
        )
        os.close(archive_fd)

        archive_path = Path(archive_name)

        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=timeout,
            ) as client:
                try:
                    commit_response = await client.get(
                        f"{self.GITHUB_API}/repos/{full_name}/commits/{branch}",
                        headers=headers,
                    )
                    commit_response.raise_for_status()

                    commit_data = commit_response.json()
                    commit_sha = commit_data.get("sha")

                    if not isinstance(commit_sha, str) or not commit_sha:
                        raise RepositoryDownloadError(
                            "GitHub returned an invalid commit reference."
                        )

                    archive_url = (
                        f"{self.GITHUB_API}/repos/{full_name}/tarball/{commit_sha}"
                    )

                    downloaded_size = 0

                    async with client.stream(
                        "GET",
                        archive_url,
                        headers=headers,
                    ) as response:
                        response.raise_for_status()

                        content_length = response.headers.get("content-length")

                        if content_length:
                            try:
                                if int(content_length) > settings.REPOSITORY_MAX_ARCHIVE_SIZE:
                                    raise RepositoryDownloadError(
                                        "Repository archive exceeds the download size limit."
                                    )
                            except ValueError:
                                pass

                        with archive_path.open("wb") as archive_file:
                            async for chunk in response.aiter_bytes():
                                downloaded_size += len(chunk)

                                if downloaded_size > settings.REPOSITORY_MAX_ARCHIVE_SIZE:
                                    raise RepositoryDownloadError(
                                        "Repository archive exceeds the download size limit."
                                    )

                                archive_file.write(chunk)

                except RepositoryDownloadError:
                    raise

                except httpx.HTTPStatusError as exc:
                    raise RepositoryDownloadError(
                        f"GitHub returned HTTP {exc.response.status_code}"
                    ) from exc

                except (httpx.RequestError, ValueError, KeyError) as exc:
                    raise RepositoryDownloadError(
                        "Unable to download repository from GitHub."
                    ) from exc

            if downloaded_size == 0:
                raise RepositoryDownloadError(
                    "GitHub returned an empty repository archive."
                )

            try:
                await asyncio.to_thread(
                    self._extract_archive,
                    archive_path,
                    destination,
                )
            except RepositoryDownloadError:
                raise
            except Exception as exc:
                raise RepositoryDownloadError(
                    "Unable to safely extract repository archive."
                ) from exc

            return commit_sha

        finally:
            archive_path.unlink(missing_ok=True)

    def _extract_archive(
        self,
        archive_path: Path,
        destination: Path,
    ):
        destination.mkdir(parents=True, exist_ok=True)
        destination = destination.resolve()

        files_count = 0
        total_size = 0

        try:
            with tarfile.open(archive_path, mode="r:gz") as tar:
                for member in tar:
                    if not member.isfile():
                        continue

                    raw_name = member.name

                    if not raw_name or "\\" in raw_name or "\x00" in raw_name:
                        continue

                    relative = PurePosixPath(raw_name)

                    if relative.is_absolute() or ".." in relative.parts:
                        continue

                    parts = relative.parts

                    # GitHub archives contain a single top-level directory.
                    if len(parts) < 2:
                        continue

                    parts = parts[1:]

                    if not parts or any(
                        part in self.IGNORED_DIRS for part in parts[:-1]
                    ):
                        continue

                    filename = parts[-1]

                    if (
                        filename not in self.ALLOWED_NAMES
                        and Path(filename).suffix.lower()
                        not in self.ALLOWED_SUFFIXES
                    ):
                        continue

                    if member.size <= 0:
                        continue

                    if member.size > settings.REPOSITORY_MAX_FILE_SIZE:
                        continue

                    if files_count >= settings.REPOSITORY_MAX_FILES:
                        break

                    if (
                        total_size + member.size
                        > settings.REPOSITORY_MAX_TOTAL_SIZE
                    ):
                        break

                    target = destination.joinpath(*parts)

                    try:
                        target.resolve().relative_to(destination)
                    except (OSError, ValueError):
                        continue

                    target.parent.mkdir(parents=True, exist_ok=True)

                    source = tar.extractfile(member)

                    if source is None:
                        continue

                    with source:
                        content = source.read(
                            settings.REPOSITORY_MAX_FILE_SIZE + 1
                        )

                    if len(content) != member.size:
                        continue

                    if b"\x00" in content:
                        continue

                    target.write_bytes(content)

                    files_count += 1
                    total_size += len(content)

        except (tarfile.TarError, OSError) as exc:
            raise RepositoryDownloadError(
                "Repository archive is invalid or could not be extracted."
            ) from exc

        if files_count == 0:
            raise RepositoryDownloadError(
                "No supported source files were found in this repository."
            )


repository_download_service = RepositoryDownloadService()
