"""Validate release routing, refs, versions, and built distribution contents."""

from __future__ import annotations

import argparse
import email.parser
import gzip
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile
import tomllib
import urllib.request
import zipfile

FINAL_TAG_RE = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\.post[1-9][0-9]*)?)$")
TARGETS = {
    "pypi": "https://upload.pypi.org/legacy/",
    "testpypi": "https://test.pypi.org/legacy/",
}
COLLECTION_ROOT = "ansible_collections/emersonfelipesp/netbox_openbao/"
REQUIRED_COLLECTION_FILES = {
    "LICENSE",
    "README.md",
    "galaxy.yml",
    "meta/runtime.yml",
    "plugins/lookup/credential.py",
    "plugins/module_utils/openbao.py",
}
GALAXY_REQUIRED_FILES = REQUIRED_COLLECTION_FILES - {"galaxy.yml"}
ALLOWED_GALAXY_ROOTS = {"docs", "meta", "plugins"}
ALLOWED_GALAXY_FILES = {"FILES.json", "LICENSE", "MANIFEST.json", "README.md"}


def select_target(target: str) -> tuple[str, str]:
    """Return the approved target and upload URL or reject an unknown index."""
    try:
        return target, TARGETS[target]
    except KeyError as exc:
        raise ValueError(f"unsupported release target: {target}") from exc


def project_version(repository: pathlib.Path) -> str:
    """Read the PEP 621 version."""
    with (repository / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["project"]["version"]


def galaxy_version(repository: pathlib.Path) -> str:
    """Read the collection version without executing or importing repository code."""
    text = (repository / "galaxy.yml").read_text(encoding="utf-8")
    matches = re.findall(r"(?m)^version:\s*['\"]?([^\s'\"]+)['\"]?\s*$", text)
    if len(matches) != 1:
        raise ValueError("galaxy.yml must contain exactly one scalar version")
    return matches[0]


def git_commit(repository: pathlib.Path, ref: str) -> str:
    """Resolve a Git ref to its commit using fixed arguments."""
    result = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", f"{ref}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def git_object_type(repository: pathlib.Path, ref: str) -> str:
    """Read a Git object's type using fixed arguments."""
    result = subprocess.run(
        ["git", "-C", str(repository), "cat-file", "-t", ref],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def validate_release_ref(repository: pathlib.Path, tag: str, main_ref: str) -> tuple[str, str]:
    """Require an existing final tag at canonical main with aligned package versions."""
    match = FINAL_TAG_RE.fullmatch(tag)
    if not match:
        raise ValueError(f"release tag is not an approved final tag: {tag}")
    if git_object_type(repository, f"refs/tags/{tag}") != "tag":
        raise ValueError(f"release tag must be annotated: {tag}")

    version = match.group("version")
    source_sha = git_commit(repository, f"refs/tags/{tag}")
    main_sha = git_commit(repository, main_ref)
    if source_sha != main_sha:
        raise ValueError(f"tag {tag} ({source_sha}) is not canonical main ({main_sha})")

    declared = {project_version(repository), galaxy_version(repository)}
    if declared != {version}:
        raise ValueError(f"tag version {version} does not match declared versions: {sorted(declared)}")
    return version, source_sha


def wheel_members(path: pathlib.Path) -> set[str]:
    """Return wheel member names."""
    with zipfile.ZipFile(path) as archive:
        return set(archive.namelist())


def sdist_members(path: pathlib.Path) -> set[str]:
    """Return source-distribution members without extracting them."""
    with tarfile.open(path, "r:gz") as archive:
        return {member.name for member in archive.getmembers()}


def verify_wheel(path: pathlib.Path, version: str) -> None:
    """Assert that the wheel carries the collection at Ansible's namespace path."""
    members = wheel_members(path)
    expected = {COLLECTION_ROOT + item for item in REQUIRED_COLLECTION_FILES}
    missing = sorted(expected - members)
    if missing:
        raise ValueError(f"wheel is missing collection files: {missing}")

    metadata_name = f"netbox_openbao_ansible-{version}.dist-info/METADATA"
    if metadata_name not in members:
        raise ValueError(f"wheel is missing metadata: {metadata_name}")
    with zipfile.ZipFile(path) as archive:
        metadata = email.parser.Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
    if metadata["Name"] != "netbox-openbao-ansible" or metadata["Version"] != version:
        raise ValueError("wheel metadata name or version does not match the release")


def verify_sdist(path: pathlib.Path, version: str) -> None:
    """Assert that the sdist contains every collection source required to rebuild."""
    prefix = f"netbox_openbao_ansible-{version}/"
    members = sdist_members(path)
    missing = sorted(prefix + item for item in REQUIRED_COLLECTION_FILES if prefix + item not in members)
    if missing:
        raise ValueError(f"sdist is missing collection files: {missing}")


def verify_dist(directory: pathlib.Path, version: str) -> None:
    """Require exactly one wheel and one sdist, then verify both."""
    wheels = sorted(directory.glob("*.whl"))
    sdists = sorted(directory.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise ValueError(f"expected one wheel and one sdist, got {len(wheels)} and {len(sdists)}")
    verify_wheel(wheels[0], version)
    verify_sdist(sdists[0], version)


def normalize_sdist(path: pathlib.Path, epoch: int) -> None:
    """Rewrite an sdist with stable ordering and ownership, time, and gzip metadata."""
    if epoch < 0:
        raise ValueError("source epoch must be non-negative")
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            if not member.isfile() and not member.isdir():
                raise ValueError(f"unsupported sdist member type: {member.name}")
            extracted = source.extractfile(member) if member.isfile() else None
            entries.append((member, extracted.read() if extracted is not None else None))

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for original, content in sorted(entries, key=lambda entry: entry[0].name):
            member = tarfile.TarInfo(original.name)
            member.type = original.type
            member.mode = original.mode
            member.mtime = epoch
            member.uid = member.gid = 0
            member.uname = member.gname = ""
            member.size = len(content) if content is not None else 0
            archive.addfile(member, io.BytesIO(content) if content is not None else None)

    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed:
            compressed.write(buffer.getvalue())


def verify_index_hashes(directory: pathlib.Path, version: str, metadata: dict[str, object]) -> None:
    """Require TestPyPI to contain the exact local wheel and sdist bytes."""
    if metadata.get("info", {}).get("version") != version:
        raise ValueError("index metadata version does not match the release")
    expected = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.iterdir())
        if path.is_file()
    }
    published = {
        item["filename"]: item.get("digests", {}).get("sha256")
        for item in metadata.get("urls", [])
    }
    if published != expected:
        raise ValueError("index artifacts do not match the validated local distributions")


def testpypi_metadata(version: str) -> dict[str, object]:
    """Fetch immutable TestPyPI metadata for one version."""
    url = f"https://test.pypi.org/pypi/netbox-openbao-ansible/{version}/json"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def download_testpypi(directory: pathlib.Path, version: str) -> None:
    """Download and authenticate the exact TestPyPI artifacts selected for PyPI."""
    metadata = testpypi_metadata(version)
    if metadata.get("info", {}).get("version") != version:
        raise ValueError("index metadata version does not match the release")
    expected_names = {
        f"netbox_openbao_ansible-{version}-py3-none-any.whl",
        f"netbox_openbao_ansible-{version}.tar.gz",
    }
    releases = {item["filename"]: item for item in metadata.get("urls", [])}
    if set(releases) != expected_names:
        raise ValueError("TestPyPI does not contain the exact release artifact pair")
    directory.mkdir(parents=True, exist_ok=False)
    for name in sorted(expected_names):
        item = releases[name]
        with urllib.request.urlopen(item["url"], timeout=60) as response:
            content = response.read()
        digest = hashlib.sha256(content).hexdigest()
        if digest != item.get("digests", {}).get("sha256"):
            raise ValueError(f"TestPyPI artifact digest mismatch: {name}")
        (directory / name).write_bytes(content)
    verify_dist(directory, version)


def verify_galaxy(directory: pathlib.Path, version: str) -> None:
    """Require one clean Galaxy archive with aligned metadata and collection sources."""
    archive_path = _only_galaxy_archive(directory)
    members = sdist_members(archive_path)
    missing = sorted(GALAXY_REQUIRED_FILES - members)
    if missing:
        raise ValueError(f"Galaxy archive is missing collection files: {missing}")
    unexpected = _unexpected_galaxy_members(members)
    if unexpected:
        raise ValueError(f"Galaxy archive contains unexpected files: {unexpected}")
    if _galaxy_manifest_version(archive_path) != version:
        raise ValueError("Galaxy manifest version does not match the release")


def _only_galaxy_archive(directory: pathlib.Path) -> pathlib.Path:
    """Return the only Galaxy archive in a build directory."""
    archives = sorted(directory.glob("*.tar.gz"))
    if len(archives) != 1:
        raise ValueError(f"expected one Galaxy archive, got {len(archives)}")
    return archives[0]


def _unexpected_galaxy_members(members: set[str]) -> list[str]:
    """List archive members outside the intentional runtime/documentation allowlist."""
    unexpected = []
    for member in members:
        path = pathlib.PurePosixPath(member)
        root = path.parts[0] if path.parts else ""
        if member not in ALLOWED_GALAXY_FILES and root not in ALLOWED_GALAXY_ROOTS:
            unexpected.append(member)
    return sorted(unexpected)


def _galaxy_manifest_version(archive_path: pathlib.Path) -> str | None:
    """Read the generated Galaxy manifest version."""
    with tarfile.open(archive_path, "r:gz") as archive:
        try:
            manifest_file = archive.extractfile("MANIFEST.json")
        except KeyError as exc:
            raise ValueError("Galaxy archive is missing MANIFEST.json") from exc
        manifest_data = json.load(manifest_file) if manifest_file is not None else {}
    return manifest_data.get("collection_info", {}).get("version")


def main() -> None:
    """Run one release-policy command."""
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    route = subparsers.add_parser("route")
    route.add_argument("--target", required=True)

    release_ref = subparsers.add_parser("validate-ref")
    release_ref.add_argument("--repository", type=pathlib.Path, default=pathlib.Path("."))
    release_ref.add_argument("--tag", required=True)
    release_ref.add_argument("--main-ref", default="refs/release-policy/main")
    release_ref.add_argument("--github-output", type=pathlib.Path)

    distribution = subparsers.add_parser("verify-dist")
    distribution.add_argument("--directory", type=pathlib.Path, default=pathlib.Path("dist"))
    distribution.add_argument("--version", required=True)

    normalize = subparsers.add_parser("normalize-sdist")
    normalize.add_argument("--path", type=pathlib.Path, required=True)
    normalize.add_argument("--epoch", type=int, required=True)

    galaxy = subparsers.add_parser("verify-galaxy")
    galaxy.add_argument("--directory", type=pathlib.Path, default=pathlib.Path("galaxy-dist"))
    galaxy.add_argument("--version", required=True)

    index = subparsers.add_parser("verify-testpypi")
    index.add_argument("--directory", type=pathlib.Path, default=pathlib.Path("dist"))
    index.add_argument("--version", required=True)

    download = subparsers.add_parser("download-testpypi")
    download.add_argument("--directory", type=pathlib.Path, default=pathlib.Path("public-dist"))
    download.add_argument("--version", required=True)

    args = parser.parse_args()
    if args.command == "route":
        print("\t".join(select_target(args.target)))
        return
    if args.command == "verify-dist":
        verify_dist(args.directory, args.version)
        return
    if args.command == "normalize-sdist":
        normalize_sdist(args.path, args.epoch)
        return
    if args.command == "verify-galaxy":
        verify_galaxy(args.directory, args.version)
        return
    if args.command == "verify-testpypi":
        verify_index_hashes(args.directory, args.version, testpypi_metadata(args.version))
        return
    if args.command == "download-testpypi":
        download_testpypi(args.directory, args.version)
        return

    version, source_sha = validate_release_ref(args.repository, args.tag, args.main_ref)
    values = f"version={version}\nsource_sha={source_sha}\n"
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(values)
    else:
        print(values, end="")


if __name__ == "__main__":
    main()
