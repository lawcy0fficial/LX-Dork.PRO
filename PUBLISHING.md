# Publishing LX-Dork-Pro to PyPI

This covers the steps I can't do for you from here — uploading needs your
own PyPI account and API token, which I have no way to obtain or use on
your behalf. Everything else (package metadata, build, verification) is
already done; the `dist/` folder in this zip contains a real, tested
sdist + wheel built from this exact codebase.

## 0. Before you do anything else: confirm the name is still free

I checked and found no existing `lx-dork-pro` project on PyPI as of this
writing, but names can be claimed at any time. Confirm right before you
publish:

```
https://pypi.org/project/lx-dork-pro/
```

A 404 means it's still available. If it's taken by the time you get here,
pick a new name and change `name = "..."` in `pyproject.toml` (the
importable package stays `lxdorkpro` either way — only the PyPI/pip-install
name changes).

## 1. Fill in your real repository URL

`pyproject.toml` currently has the `[project.urls]` section commented out
rather than pointing at a fake `github.com/example/...` link. If you have
(or plan to have) a real repo, uncomment and fill in:

```toml
[project.urls]
Homepage = "https://github.com/<you>/lx-dork-pro"
Issues = "https://github.com/<you>/lx-dork-pro/issues"
Changelog = "https://github.com/<you>/lx-dork-pro/blob/main/CHANGELOG.md"
```

## 2. Create accounts + API tokens

You need both — **always test on TestPyPI first**, since a bad upload to
real PyPI can't be deleted, only yanked (still visible, just discouraged).

1. https://test.pypi.org/account/register/ — TestPyPI account (separate from real PyPI)
2. https://pypi.org/account/register/ — real PyPI account
3. Enable 2FA on both (PyPI requires it for uploads)
4. Generate an API token for each:
   - TestPyPI: https://test.pypi.org/manage/account/token/
   - PyPI: https://pypi.org/manage/account/token/
   - Scope each token to "Entire account" for your first upload (a project
     doesn't exist yet to scope a token to), then re-scope to just this
     project once it exists

Store tokens somewhere safe — they're shown once. A `~/.pypirc` file or
your password manager both work; don't commit them anywhere.

## 3. Set up the tooling (on your machine, not this sandbox)

```bash
python3 -m venv venv && source venv/bin/activate
pip install build twine
```

## 4. Build fresh artifacts

The `dist/` folder here already has a built sdist + wheel, but rebuild on
your machine to be sure nothing sandbox-specific leaked in:

```bash
rm -rf dist build *.egg-info
python -m build
```

This produces `dist/lx_dork_pro-1.10.0-py3-none-any.whl` and
`dist/lx-dork-pro-1.10.0.tar.gz` (matching whatever `version` is currently
set in `pyproject.toml` — see step 9 below for what to do when that
changes).

## 5. Check the build

```bash
twine check dist/*
```

Should print `PASSED` for both files. This catches common metadata issues
(malformed README rendering, missing classifiers, etc.) before you upload.

## 6. Upload to TestPyPI first

```bash
twine upload --repository testpypi dist/*
```

When prompted: username is `__token__`, password is the TestPyPI token
(including the `pypi-` prefix).

Then install from TestPyPI into a clean venv to confirm it actually works:

```bash
python3 -m venv test_install && source test_install/bin/activate
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ lx-dork-pro
lxdorkpro --version
lxdorkpro dork -d 'inurl:admin site:example.com' -e duckduckgo
```

The `--extra-index-url` is needed because TestPyPI doesn't mirror real
PyPI's packages, so `click`/`rich`/`requests`/`beautifulsoup4` need to come
from the real index while `lx-dork-pro` itself comes from Test.

## 7. Upload to real PyPI

Once the TestPyPI install works correctly:

```bash
twine upload dist/*
```

Username `__token__`, password your real PyPI token.

## 8. Verify the real thing

```bash
pip install lx-dork-pro
lxdorkpro --version
```

## 9. Future releases

Each new version needs a version bump in **two places** before rebuilding
(these are meant to always match — nothing enforces it automatically):

- `lxdorkpro/__init__.py` → `__version__`
- `pyproject.toml` → `version`

Then repeat steps 4–7. PyPI never lets you re-upload the same version
number, even if you delete the release first — always bump.

## What I already verified for you

- `pyproject.toml` parses as valid TOML and `pip install -e .` works from it
- Built a real sdist and wheel in this environment using setuptools' PEP 517
  hooks directly (no network needed for the build itself)
- Installed the actual built wheel into a **clean virtual environment**
  (not just this project's working directory) and confirmed:
  - `lxdorkpro --version` and `lxdorkpro --help` both work
  - `python -m lxdorkpro --version` works
  - The `lx-dork-pro` → `lxdorkpro` package name mapping resolves correctly
- Inspected the wheel's `METADATA` file directly: `Description-Content-Type:
  text/markdown` is set correctly (so your README renders as Markdown on
  the PyPI page, not as a wall of raw text — a very common first-timer bug)
- Confirmed all 31 modules (including `tui_pro/`) and the console-script
  entry point (`lxdorkpro = lxdorkpro.cli:main`) are present in the built
  wheel

What I could **not** verify (needs your machine or real accounts):
`twine check` (twine isn't installed here and there's no network to add
it), the actual TestPyPI/PyPI upload, and installing from the real index
over the network.
