# MithrilHook contribution workflow

The owner decides integration and release publication. Work on descriptive
branches and propose changes for review. Do not merge or self-approve a PR,
force-update shared branches, or publish a release without owner direction.

Preserve upstream license notices and exact provenance. Production uses the
strict core directly; do not reintroduce a weaker mode or legacy API aliases.
Use English for repository text. Preserve C17 sources and C++17 native fixtures.

Review source and export changes explicitly. Refresh metadata/SOURCE_MANIFEST.json
only for intended changes, then run scripts/verify_sources.py and appropriate
portable/native tests. Keep generated output under build/ or dist/. Do not
weaken a test or accept an unrelated crash/timeout as a negative control.

Separate portable/projected-API execution, Windows cross-compilation, genuine
Windows/MSVC/clang-cl execution, and application/game acceptance in reports.
Inherited evidence validates its recorded source, not new MithrilHook bytes.
