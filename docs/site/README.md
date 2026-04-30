# authsome docs

The Mintlify documentation site for [authsome](https://github.com/manojbajaj95/authsome).

## Local preview

Requires Node.js `>=20.17.0`.

```bash
npm i -g mint
mint dev
```

The site renders at `http://localhost:3000` with hot reload.

## Validate before committing

```bash
mint broken-links     # check internal links
mint a11y             # check accessibility issues
mint validate         # run schema + content validation
```

## Structure

```
docs/site/
  docs.json                    Mintlify config: theme, navigation, navbar
  index.mdx                    Landing page
  quickstart.mdx               First-run walkthrough
  guides/                      Task-oriented guides
  concepts/                    Architecture and core concepts
  reference/                   CLI, schema, env vars, bundled providers
  troubleshooting/             Diagnostic pages
```

## Adding a page

1. Create the MDX file in the right subfolder.
2. Add it to the appropriate `pages` list in `docs.json` — pages not referenced in `docs.json` are hidden from the sidebar.
3. Run `mint dev` to preview, then `mint broken-links` and `mint validate` before opening a PR.

## Style

Match the surrounding pages:

- Sentence case for headings.
- Code blocks always have a language tag.
- Internal links use root-relative paths without file extensions: `/guides/login-with-oauth`, not `./login-with-oauth.mdx`.
- Prefer Mintlify components (`<Steps>`, `<CodeGroup>`, `<Tabs>`, `<Card>`, `<Columns>`, `<Tip>`, `<Warning>`) over plain Markdown when they help.
