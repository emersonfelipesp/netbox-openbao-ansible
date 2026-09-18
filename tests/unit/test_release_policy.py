from __future__ import annotations

import hashlib
import io
import os
import pathlib
import subprocess
import sys
import tarfile
import zipfile

import pytest
import yaml

from scripts.release_policy import (
    galaxy_version,
    normalize_sdist,
    project_version,
    select_target,
    validate_release_ref,
    verify_dist,
    verify_galaxy,
    verify_index_hashes,
)

ROOT = pathlib.Path(__file__).parents[2]
PUBLIC = ROOT / ".github/workflows/publish.yml"
GITHUB_CI = ROOT / ".github/workflows/ci.yml"
GITEA_PACKAGE = ROOT / ".gitea/workflows/publish-package.yml"


def test_declared_versions_are_aligned():
    assert project_version(ROOT) == galaxy_version(ROOT) == "0.1.0"


def test_galaxy_build_excludes_local_release_artifacts():
    galaxy = yaml.safe_load((ROOT / "galaxy.yml").read_text(encoding="utf-8"))
    for excluded in (
        ".ansible",
        ".cache",
        ".gitignore",
        ".venv",
        ".uv-cache",
        "dist",
        "pyproject.toml",
        "python-dist",
        "scripts",
        "tests",
        "*.egg-info",
    ):
        assert excluded in galaxy["build_ignore"]


@pytest.mark.parametrize(
    ("target", "url"),
    [
        ("pypi", "https://upload.pypi.org/legacy/"),
        ("testpypi", "https://test.pypi.org/legacy/"),
    ],
)
def test_release_target_is_explicit(target, url):
    assert select_target(target) == (target, url)


def test_unknown_release_target_is_rejected():
    with pytest.raises(ValueError, match="unsupported"):
        select_target("some-index")


def test_final_tag_must_equal_canonical_main(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Release Test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "release@example.invalid"], check=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "galaxy.yml").write_text("version: 0.1.0\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "release"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "tag", "-a", "v0.1.0", "-m", "Release 0.1.0"],
        check=True,
    )
    subprocess.run(["git", "-C", str(tmp_path), "branch", "release-main"], check=True)

    version, source_sha = validate_release_ref(tmp_path, "v0.1.0", "release-main")
    assert version == "0.1.0"
    assert len(source_sha) == 40

    (tmp_path / "later").write_text("later", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "later"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "branch", "-f", "release-main"], check=True)
    with pytest.raises(ValueError, match="not canonical main"):
        validate_release_ref(tmp_path, "v0.1.0", "release-main")


@pytest.mark.parametrize("tag", ["0.1.0", "v0.1", "v0.1.0rc1", "v0.1.0.post0", "v0.1.0;bad"])
def test_non_final_or_unsafe_tags_are_rejected(tmp_path, tag):
    with pytest.raises(ValueError, match="approved final tag"):
        validate_release_ref(tmp_path, tag, "main")


def test_lightweight_release_tag_is_rejected(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Release Test"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "release@example.invalid"], check=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
    (tmp_path / "galaxy.yml").write_text("version: 0.1.0\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "release"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "tag", "v0.1.0"], check=True)
    with pytest.raises(ValueError, match="must be annotated"):
        validate_release_ref(tmp_path, "v0.1.0", "main")


@pytest.mark.parametrize("path", [PUBLIC, GITHUB_CI, GITEA_PACKAGE])
def test_release_workflow_yaml_and_shell_blocks_parse(path):
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(workflow, dict)
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            script = step.get("run")
            if not isinstance(script, str):
                continue
            result = subprocess.run(
                ["/bin/bash", "-n"], input=script, capture_output=True, text=True, timeout=10
            )
            assert result.returncode == 0, f"{path}: {step.get('name')}: {result.stderr}"


def test_release_actions_are_immutable_sha_pinned():
    for path in (PUBLIC, GITHUB_CI, GITEA_PACKAGE):
        for line in path.read_text(encoding="utf-8").splitlines():
            if "uses:" not in line:
                continue
            revision = line.split("uses:", 1)[1].split("#", 1)[0].strip().rsplit("@", 1)[1]
            assert len(revision) == 40
            assert all(character in "0123456789abcdef" for character in revision)


def test_public_credentials_are_target_isolated_without_oidc():
    text = PUBLIC.read_text(encoding="utf-8")
    publish = text.split("  publish:", 1)[1]
    assert "id-token: write" not in text
    assert publish.count("pypa/gh-action-pypi-publish@") == 2
    assert "secrets.TEST_PYPI_USERNAME" in publish
    assert "secrets.TEST_PYPI_TOKEN" in publish
    assert "secrets.PYPI_TOKEN" in publish
    assert "secrets.PYPI_USERNAME" not in publish
    assert publish.count("attestations: false") == 2


def test_gitea_package_credentials_are_isolated():
    text = GITEA_PACKAGE.read_text(encoding="utf-8")
    assert text.count("secrets.PACKAGE_WRITE_TOKEN") == 1
    assert "secrets.PYPI_TOKEN" not in text
    assert "secrets.TEST_PYPI_TOKEN" not in text


def test_github_ci_covers_supported_interpreters():
    text = GITHUB_CI.read_text(encoding="utf-8")
    assert 'python-version: ["3.11", "3.12", "3.13", "3.14"]' in text


def test_final_publication_requires_a_github_release():
    workflow = yaml.safe_load(PUBLIC.read_text(encoding="utf-8"))
    triggers = workflow[True]
    assert triggers["release"]["types"] == ["published"]
    assert "pypi" not in triggers["workflow_dispatch"]["inputs"].get("target", {}).get("options", [])


def test_testpypi_hashes_must_match_local_distributions(tmp_path):
    wheel = tmp_path / "netbox_openbao_ansible-0.1.0-py3-none-any.whl"
    sdist = tmp_path / "netbox_openbao_ansible-0.1.0.tar.gz"
    wheel.write_bytes(b"wheel")
    sdist.write_bytes(b"sdist")
    metadata = {
        "info": {"version": "0.1.0"},
        "urls": [
            {"filename": path.name, "digests": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()}}
            for path in (wheel, sdist)
        ],
    }
    verify_index_hashes(tmp_path, "0.1.0", metadata)
    metadata["urls"][0]["digests"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="do not match"):
        verify_index_hashes(tmp_path, "0.1.0", metadata)


def test_sdist_normalization_is_reproducible(tmp_path):
    archives = []
    for suffix, mtime in (("a", 1), ("b", 2)):
        archive_path = tmp_path / f"source-{suffix}.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            member = tarfile.TarInfo("project-0.1.0/module.py")
            member.size = len(b"value = 1\n")
            member.mtime = mtime
            member.uid = mtime
            archive.addfile(member, io.BytesIO(b"value = 1\n"))
        normalize_sdist(archive_path, 1_700_000_000)
        archives.append(archive_path.read_bytes())
    assert archives[0] == archives[1]


def test_built_distributions_have_the_collection_namespace(tmp_path):
    subprocess.run([sys.executable, "-m", "build", "--outdir", str(tmp_path), str(ROOT)], check=True)
    verify_dist(tmp_path, "0.1.0")

    wheel = next(tmp_path.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        assert (
            "ansible_collections/emersonfelipesp/netbox_openbao/plugins/lookup/credential.py"
            in archive.namelist()
        )


def test_galaxy_archive_is_clean_and_versioned(tmp_path):
    ansible_home = tmp_path / "home"
    ansible_home.mkdir()
    subprocess.run(
        [
            str(pathlib.Path(sys.executable).with_name("ansible-galaxy")),
            "collection",
            "build",
            "--output-path",
            str(tmp_path),
        ],
        cwd=ROOT,
        env={**os.environ, "HOME": str(ansible_home)},
        check=True,
    )
    verify_galaxy(tmp_path, "0.1.0")
