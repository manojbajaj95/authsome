# Contributing to authsome

> **Do one thing and do it well.**
> authsome manages credentials — nothing more. Every contribution should make that one job simpler, more secure, or more reliable. If a change expands scope beyond credential management, it probably belongs in a different tool.

---

## Table of contents

- [Engineering principles](#engineering-principles)
- [AI-assisted development](#ai-assisted-development)
- [Getting started](#getting-started)
- [Making changes](#making-changes)
- [Running tests](#running-tests)
- [Lint and type checks](#lint-and-type-checks)
- [Extending authsome](#extending-authsome)
- [Submitting a PR](#submitting-a-pr)
- [Reporting bugs / requesting features](#reporting-bugs--requesting-features)
- [License](#license)

---

## Engineering principles

These principles apply to all contributions — human and AI alike.

**YAGNI — You Aren't Gonna Need It.**
Implement only what the current task demands. Build for today's requirements; future requirements will arrive with future context.

**Use trusted libraries over reinventing.**
Reach for a well-maintained dependency before writing your own crypto, HTTP client, or token parser. The goal is a working credential manager, not a showcase of custom implementations. When a library exists and is maintained, use it.

**Deep modules over shallow ones.**
Prefer a module with a small surface area and rich internals over a sprawl of thin wrappers. A single `AuthClient` that handles everything cleanly beats a dozen one-method classes. More files is not more modular.

**Single responsibility and separation of concerns.**
Auth authenticates. Vault stores credentials. The CLI presents output. These boundaries are not negotiable — a flow should not write to storage, and storage should not know about OAuth. If a function is hard to name, it's doing too many things.

**Premature optimization is evil.**
Don't add caching, batching, or concurrency before you have a measured performance problem. Simple code that's slow is fixable; complex code that's wrong is not.

**Don't do it just because you can.**
Clever is a cost, not a benefit. If a feature, abstraction, or refactor isn't directly solving a real problem that exists today, skip it.

**Leave it better than you found it.**
Every change is an opportunity to fix a nearby typo, remove a dead import, or clarify a confusing comment — not the whole file, just the immediate vicinity. Small improvements compound.

**Comment the why, not the what.**
Use Google-style docstrings for all public interfaces. Inline comments should explain non-obvious invariants, workarounds, or hidden constraints — not restate what the code already says clearly.

**Update docs alongside code.**
If you change behavior, update the relevant docstring, `README.md`, or this file in the same commit. Documentation debt accumulates faster than technical debt and is harder to pay down later.

---

## AI-assisted development

When using an AI coding assistant (Claude Code, Copilot, Codex, etc.), these additional practices apply.

**Verify before claiming done.**
Run `uv run pytest`, `uv run ruff check`, and `uv run ty check` and confirm they pass before stating work is complete. Never assume. Plausible-sounding output is not the same as passing output.

**Minimal blast radius.**
Fix only what you were asked to fix. Don't refactor surrounding code, rename variables, or reorganize imports while implementing a feature. Save cleanup for a dedicated commit so diffs stay reviewable.

**Surface uncertainty.**
If there are multiple valid approaches, say so and present the tradeoffs. Silently picking one and hiding the decision makes review harder and leads to avoidable rework.

**No hallucinated APIs.**
If you're unsure a method, parameter, or module exists, search for it in the codebase before using it. Plausible-sounding code that doesn't run wastes more time than asking first.

**Read before write.**
Understand the existing implementation before modifying it. Assumptions about structure lead to subtle bugs that are expensive to diagnose.

**Prefer reversible changes.**
Avoid destructive operations — dropping data, force-pushing, deleting files — without explicit confirmation. When in doubt, ask rather than act.

**Small, focused commits.**
One logical change per commit. AI agents tend to batch too many unrelated changes; resist this. It makes review easier and blame more useful.

**Explain the why in commit messages.**
The diff shows what changed. The commit message should say why. Future readers (and future AI sessions) will thank you.

---

## Getting started

```bash
git clone https://github.com/manojbajaj95/authsome.git
cd authsome
uv pip install -e ".[dev]"
pre-commit install          # runs ruff automatically on every commit
```

---

## Making changes

| Convention | Details |
|---|---|
| **Commits** | [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`, `chore:`, `docs:`, `refactor:` |
| **Breaking changes** | Append `!` (e.g. `feat!:`) or add a `BREAKING CHANGE:` footer |
| **Branch names** | `feat/<short-description>`, `fix/<short-description>` |
| **PR scope** | One logical change per PR |

---

## Running tests

```bash
pytest                           # all tests
pytest tests/test_client.py      # single file
pytest -k test_login_pkce -v     # single test by name
pytest --cov=authsome            # with coverage report
```

All tests must pass before opening a PR.

---

## Lint and type checks

```bash
ruff check --fix src/ tests/     # lint + auto-fix
ruff format src/ tests/          # format
ty check src/                    # type check
```

Or run everything at once:

```bash
pre-commit run --all-files
```

---

## Extending authsome

### Adding a new provider

1. Create `src/authsome/bundled_providers/<name>.json` following the `ProviderDefinition` schema.
2. Add a test in `tests/` that covers at least the config-loading path.
3. Document the provider in `README.md`.

### Adding a new auth flow

1. Implement `AuthFlow.authenticate()` in `src/authsome/flows/`.
2. Register it in `FlowType` and `_FLOW_HANDLERS` in `src/authsome/client.py`.
3. Cover the happy path and at least one error case in tests.

For a full description of the major subsystems (`AuthClient`, flows, provider registry, storage, crypto, models, CLI) see [CLAUDE.md](CLAUDE.md).

---

## Submitting a PR

1. **Open an issue first** for non-trivial changes so we can align on approach.
2. Push your branch and open a PR against `main`.
3. Describe *what* changed and *why* in the PR body.
4. A maintainer will review within a few days.

---

## Reporting bugs / requesting features

Use the [GitHub issue templates](.github/ISSUE_TEMPLATE/) — there are dedicated forms for bug reports and feature requests.

---

## License

By contributing you agree that your changes will be released under the [MIT License](LICENSE).
