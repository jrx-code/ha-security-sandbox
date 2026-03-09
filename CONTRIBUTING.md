# Contributing

Thanks for your interest in contributing to HA Security Sandbox!

## Getting Started

1. Fork the repository
2. Clone your fork and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Install dependencies:
   ```bash
   pip install -r ha-sandbox/requirements.txt
   ```
4. Make your changes and run the tests:
   ```bash
   cd ha-sandbox && python -m pytest tests/ -q
   ```
5. Submit a pull request

## Guidelines

- **Tests required** — all new features and bug fixes should include tests
- **One concern per PR** — keep pull requests focused on a single change
- **Code style** — we use [Ruff](https://docs.astral.sh/ruff/) for linting and formatting
- **Commits** — use [Conventional Commits](https://www.conventionalcommits.org/) format:
  - `feat:` new feature
  - `fix:` bug fix
  - `sec:` security improvement
  - `chore:` maintenance

## Adding a New Scanner

Static scanners live in `ha-sandbox/app/scanner/`. To add one:

1. Create `static_<name>.py` with a `scan_<name>_repo(repo_path) -> list[Finding]` function
2. Register it in `pipeline.py` within `run_scan()`
3. Add tests in `tests/test_phase2_<name>.py`

## Reporting Security Issues

If you discover a security vulnerability, please report it privately via GitHub Security Advisories rather than opening a public issue.
