
import asyncio
import io
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
        ".properties"
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
        "Cargo.toml"
    }

    IGNORED_DIRS = {
        ".git", "node_modules", "vendor", "dist",
        "build", ".venv", "venv", "__pycache__",
        "coverage", ".next", "target"
    }

    async def download(
        self,
        repository,
        access_token: str,
        destination: Path
    ) -> str:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        full_name = quote(repository.full_name, safe="/")
        branch = quote(repository.default_branch, safe="")

        timeout = httpx.Timeout(60, connect=10)

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout
        ) as client:
            try:
                commit_response = await client.get(
                    f"{self.GITHUB_API}/repos/{full_name}/commits/{branch}",
                    headers=headers
                )
                commit_response.raise_for_status()

                commit_sha = commit_response.json()["sha"]

                archive_url = (
                    f"{self.GITHUB_API}/repos/{full_name}/tarball/{commit_sha}"
                )

                archive_data = bytearray()

                async with client.stream(
                    "GET",
                    archive_url,
                    headers=headers
                ) as response:
                    response.raise_for_status()

                    content_length = response.headers.get("content-length")

                    if (
                        content_length
                        and int(content_length)
                        > settings.REPOSITORY_MAX_ARCHIVE_SIZE
                    ):
                        raise RepositoryDownloadError(
                            "Repository archive exceeds the download size limit"
                        )

                    async for chunk in response.aiter_bytes():
                        archive_data.extend(chunk)

                        if len(archive_data) > settings.REPOSITORY_MAX_ARCHIVE_SIZE:
                            raise RepositoryDownloadError(
                                "Repository archive exceeds the download size limit"
                            )

            except RepositoryDownloadError:
                raise

            except httpx.HTTPStatusError as exc:
                raise RepositoryDownloadError(
                    f"GitHub returned HTTP {exc.response.status_code}"
                ) from exc

            except (httpx.RequestError, ValueError, KeyError) as exc:
                raise RepositoryDownloadError(
                    "Unable to download repository from GitHub"
                ) from exc

        try:
            await asyncio.to_thread(
                self._extract_archive,
                bytes(archive_data),
                destination
            )
        except RepositoryDownloadError:
            raise
        except Exception as exc:
            raise RepositoryDownloadError(
                "Unable to safely extract repository archive"
            ) from exc

        return commit_sha

    def _extract_archive(self, archive: bytes, destination: Path):
        destination.mkdir(parents=True, exist_ok=True)

        files_count = 0
        total_size = 0

        with tarfile.open(
            fileobj=io.BytesIO(archive),
            mode="r:gz"
        ) as tar:
            for member in tar:
                if not member.isfile():
                    continue

                relative = PurePosixPath(member.name)

                if relative.is_absolute() or ".." in relative.parts:
                    continue

                parts = relative.parts

                if len(parts) < 2:
                    continue

                parts = parts[1:]

                if any(part in self.IGNORED_DIRS for part in parts[:-1]):
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

                if total_size + member.size > settings.REPOSITORY_MAX_TOTAL_SIZE:
                    break

                target = destination.joinpath(*parts)

                try:
                    target.resolve().relative_to(destination.resolve())
                except ValueError:
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)

                source = tar.extractfile(member)

                if source is None:
                    continue

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

        if files_count == 0:
            raise RepositoryDownloadError(
                "No supported source files were found in this repository"
            )


repository_download_service = RepositoryDownloadService()
