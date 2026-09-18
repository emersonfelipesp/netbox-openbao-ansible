# Release procedure

`galaxy.yml` and `pyproject.toml` carry the same version. A final release uses
an immutable `vX.Y.Z` tag at the exact commit currently on canonical `main`.
The publishing workflow refuses a missing, malformed, prerelease, stale, or
version-mismatched tag.

## Validate before tagging

Run the same gates as CI from a clean checkout:

```bash
ruff check .
python -m pytest tests/unit -q
ansible-galaxy collection build --output-path galaxy-dist/
python scripts/release_policy.py verify-galaxy --directory galaxy-dist --version 0.1.0
python -m build
python -m twine check dist/*
python scripts/release_policy.py verify-dist --directory dist --version 0.1.0
```

The distribution check requires exactly one wheel and one source archive. It
verifies their metadata and the collection files beneath
`ansible_collections/emersonfelipesp/netbox_openbao`.

## Publish

Create the final tag only after the reviewed change is on `main`, and mirror
that tag to GitHub. Run GitHub Actions workflow **Validate and publish a final
release** manually with the exact tag. Manual runs can publish only to TestPyPI:

1. Publish to TestPyPI, then independently download, hash, install, and run
   `ansible-doc -t lookup emersonfelipesp.netbox_openbao.credential` against the
   installed package.
2. Publish the GitHub Release for the validated tag. The `release: published`
   event deterministically rebuilds the reviewed tag, downloads the exact
   TestPyPI files over HTTPS, authenticates each file against TestPyPI's SHA256
   metadata, revalidates package contents, and refuses PyPI publication unless
   both artifact sets are byte-for-byte identical.
3. Repeat the independent hash, clean-install, and Ansible-discovery checks
   against PyPI.

The workflow fixes wheel timestamps to the reviewed commit and normalizes sdist
ordering, ownership, timestamps, and gzip metadata. It validates a clean build,
then transfers one authenticated artifact set to the publishing job. For PyPI,
that set consists of the exact files already published and validated on
TestPyPI, after byte equality with the fresh reviewed-source build; no unrelated
or independently rebuilt distribution reaches the final registry.
TestPyPI uses `TEST_PYPI_USERNAME` and `TEST_PYPI_TOKEN`; PyPI uses
`PYPI_TOKEN`. The jobs do not request an OIDC permission.

## Immutable recovery

PyPI and TestPyPI do not permit replacing files for an existing project
version. Never delete and recreate a version to repair a bad artifact. Fix the
source through the normal reviewed workflow, increment the version in both
metadata files, create a new final tag, and repeat TestPyPI before PyPI. A
failed upload may be retried only when registry metadata proves that no file
for that version was accepted.
