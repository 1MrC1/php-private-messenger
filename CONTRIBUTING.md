# Contributing

Thanks for looking. This is a small codebase with strong opinions; the fastest
path to a merged change is to match what is already there.

## Before you open a pull request

```sh
for t in tests/*_test.php; do php "$t"; done
for t in tests/*_runtime_test.js; do node "$t"; done
git ls-files -z '*.php' ':!:vendor/**' | xargs -0 -n1 php -l
git ls-files -z '*.js' | xargs -0 -n1 node --check
```

The `Security CI` workflow runs exactly this on PHP 8.2 and 8.3, plus
`composer audit`, CodeQL, and a secret scan — but it is **manual only**, so
nothing runs automatically on a push or a pull request. Maintainers start it from
the Actions tab when reviewing. Run the commands above yourself before pushing.

## House style

- **No new dependencies** without a good reason. There are currently two.
- **No build step.** No bundler, no transpiler, no CSS framework beyond what is
  already loaded. Plain PHP, plain JavaScript, plain CSS.
- **Don't reformat untouched lines.** The tree carries historical whitespace
  debt, and the whitespace check only looks at newly introduced changes. A diff
  that reindents a file is very hard to review.
- **Match the surrounding code**, including comment density. Comments here
  explain *why* a non-obvious control exists; they are load-bearing.
- **New user-facing strings** go in all five locale catalogs with identical keys
  and placeholders, and visible English in `index.html` must match
  `locales/en.json` verbatim. `tests/i18n_catalog_test.php` will tell you.

## Tests

Tests are plain scripts that print `PASS:` lines and throw on failure — no
framework. Many assert on source text on purpose, so that deleting a security
control fails the build. If your change makes such a test fail, do not delete the
assertion: update it and say in the pull request why the new behaviour is still
safe.

## Things that need a conversation first

Open an issue before starting on: changes to the session model, the API
allow-list, private media delivery, the upload validation chain, or anything
touching two-factor authentication. Those areas have non-obvious threat models
and a rejected pull request is a waste of your time.
