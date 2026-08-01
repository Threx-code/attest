# Reserving the distribution name

`attest-control-plane` is unclaimed on PyPI (checked: 404). `attest` is taken, which is
why the distribution name and the import name differ.

This directory builds a **placeholder** that holds the name. It ships no `attest` package
deliberately: a reservation that installed an importable module would shadow the real one
for anyone who pinned the git URL alongside it.

## Publish

Needs a PyPI API token — create one at https://pypi.org/manage/account/token/ scoped to
"Entire account" for the first upload, then narrow it to this project afterwards.

```bash
python -m build --outdir dist .packaging/reserve
twine check --strict dist/*
twine upload dist/*            # username __token__, password the pypi-… token
```

Test it first against TestPyPI if you want a rehearsal — the name is separate there, so a
mistake costs nothing:

```bash
twine upload --repository testpypi dist/*
```

## Two things that are permanent

- **A version number cannot be reused.** Uploading `0.0.1` means `0.0.1` is spent, even
  if you yank it. The real release must be `0.1.0` or later.
- **Yanking does not free the name.** Once uploaded, the project is yours and stays
  registered; that is the point, but it also means the description is public immediately.

## When the real release happens

Publish from the repository root, not from here, and let CI build it so the artefact is
the one the reproducible-build check verified.
