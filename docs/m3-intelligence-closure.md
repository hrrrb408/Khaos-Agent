# M3 Tree-sitter Intelligence — Closure Document

> Status: closed (M3 Batch 6 complete)
> Branch: `feature/m3-tree-sitter-intelligence`
> Last updated: 2026-07-12

This document is the authoritative reference for the M3 coding-intelligence
subsystem. It captures architecture, supported languages, position encoding,
ParseState lifecycle, cache limits, resolution guarantees, optional LSP
evidence fusion, known limitations, performance data, fallback behavior,
and security boundaries.

---

## 1. Architecture

```
source files
  → LanguageRegistry                    (extension → language/dialect)
  → TreeSitterAdapter                   (real grammar parse, optional)
  → ParseState (process-local cache)    (incremental reparse, bounded)
  → IndexStore                          (atomic per-file SQLite write)
  → ResolutionService                   (conservative repository resolution)
  → optional LspEvidenceFusionService   (feature flag, default OFF)
  → CodeQueryService                    (structured query facade)
```

Layers are strictly additive. Each layer may fail without breaking the
previous one. The optional Tree-sitter and LSP layers degrade gracefully:
when unavailable, the system falls back to the legacy `CodeParser` and
repository-only resolution.

### 1.1 Module layout

| Module | Responsibility |
|---|---|
| `khaos/coding/intelligence/registry.py` | Extension → language/dialect mapping |
| `khaos/coding/intelligence/index/store.py` | IndexStore: SQLite schema, atomic writes |
| `khaos/coding/intelligence/index/repository.py` | RepositoryIndexer: parse orchestration, ParseState cache |
| `khaos/coding/intelligence/resolution/` | Conservative repository resolution (imports/calls/references) |
| `khaos/coding/intelligence/lsp/` | Optional LSP evidence fusion (feature flag) |
| `khaos/coding/intelligence/query.py` | CodeQueryService: structured query facade |

---

## 2. Supported Languages and Grammar Versions

| Dialect | Tree-sitter Grammar | Locked Version |
|---|---|---|
| Python | `tree-sitter-python` | 0.25.0 |
| JavaScript | `tree-sitter-javascript` | 0.25.0 |
| TypeScript | `tree-sitter-typescript` | 0.23.2 |
| TSX | `tree-sitter-typescript` (tsx) | 0.23.2 |
| Go | `tree-sitter-go` | 0.25.0 |
| Rust | `tree-sitter-rust` | 0.24.2 |
| `tree-sitter` core | — | 0.26.0 |

All grammar versions are pinned in `pyproject.toml` under
`[project.optional-dependencies] tree-sitter`. No grammar is downloaded
at runtime; tests skip automatically when the optional dependency is
absent.

---

## 3. Position Encoding

The system uses three position encodings internally:

- **Byte offset** — used by `IndexStore`, `repository_symbols.byte_start/byte_end`
- **Code-point column** — used by query output and provenance
- **UTF-16 line/character** — used by LSP (per LSP 3.17 spec)

Conversions live in `khaos/coding/intelligence/lsp/positions.py`:

| Function | Conversion |
|---|---|
| `lsp_position_to_offsets(text, line, character_utf16)` | LSP UTF-16 → byte offset + code-point column |
| `byte_offset_to_lsp_position(text, byte_offset)` | byte offset → LSP UTF-16 (inverse) |
| `lsp_range_to_byte_offsets(text, range)` | LSP range → byte range |

Edge cases handled: ASCII, CJK (BMP), emoji (supplementary plane),
combining marks, surrogate pairs (mid-code-point clamp), CRLF / LF / CR
line endings, out-of-bounds positions (clamped).

---

## 4. ParseState Lifecycle

`ParseState` is the opaque tree-state object returned by Tree-sitter for
incremental reparsing. It is held in a process-local bounded cache in
`RepositoryParseStateCache`:

| Limit | Value |
|---|---|
| Max entries | 256 |
| Max total bytes | 64 MiB |
| Max single state | 4 MiB |
| Fixed overhead per entry | 16 KiB |

**Persistence guarantee:** `ParseState` is NEVER persisted to disk or
SQLite. It lives only in process memory and is discarded on shutdown.
The `IndexStore` schema stores only `parser_source`, `parser_version`,
`content_hash`, `generation`, and structured symbols/imports/calls —
never the native `Tree` or `ParseState`.

---

## 5. Resolution Guarantees

Repository resolution is **conservative**: a candidate is only marked
`resolved` when a unique target symbol is found via static analysis.
Ambiguous, dynamic, and external candidates are never silently resolved.

### 5.1 Status taxonomy

| Status | Meaning |
|---|---|
| `resolved` | Unique static target found in repository |
| `ambiguous` | Multiple plausible targets, cannot pick one |
| `unresolved` | No target found in repository |
| `external` | Target is outside the repository (e.g. `os`, `react`, `std::fmt`) |
| `dynamic` | Target requires runtime dispatch (e.g. `obj.method()`) |
| `invalid` | Candidate is structurally invalid |

Mutual exclusivity: every persisted edge has exactly one status. The
sum of per-status counts equals the total edge count per type.

### 5.2 Stable symbol identity

`stable_symbol_id` is a function of `(repository_id, file_path, name,
byte_start, byte_end, kind)`. It is stable across full rebuilds and
incremental updates — the same definition always produces the same ID.

### 5.3 Generation CAS

Each resolved edge carries a `generation` counter. The persistence
layer uses Compare-And-Swap: a stale (older-generation) resolution can
never overwrite a newer one. This prevents lost updates when concurrent
indexing races with resolution.

---

## 6. Optional LSP Evidence Fusion

LSP evidence fusion is **always opt-in**. The feature flag
`enable_lsp_evidence_fusion` defaults to `False` in `config.yaml`:

```yaml
coding:
  intelligence:
    lsp_evidence_fusion:
      enabled: false
      request_timeout_seconds: 5.0
      cache_max_entries: 2048
      cache_ttl_seconds: 300
      cache_max_bytes_mib: 16
```

### 6.1 Fusion pipeline

```
Tree-sitter candidate
  → Repository conservative resolution
  → optional LSP evidence (definition / references)
  → fused result (carries ALL evidence)
```

### 6.2 Six fusion rules

| Rule | Condition | Fused status |
|---|---|---|
| `repository-only` | LSP disabled / unavailable / stale | repo status |
| `lsp-confirmed` | Repo resolved + LSP same target | resolved (+0.05 confidence) |
| `lsp-promoted` | Repo unresolved/ambiguous + LSP unique internal | resolved (0.85) |
| `lsp-conflict` | Repo resolved + LSP different target | ambiguous |
| `lsp-ambiguous` | LSP returned multiple distinct internal targets | ambiguous |
| `lsp-external` | LSP points to external file(s) only | external |
| `lsp-unavailable` | LSP returned nothing / errored | repo status |
| `lsp-stale` | context generation != current generation | repo status |

### 6.3 Evidence model

Every `FusedResolution` carries a tuple of `SemanticEvidence` records:
one from `repository_resolution` plus zero or more from `lsp-definition`
/ `lsp-references`. Each evidence records its source, target file,
target range, target symbol ID, confidence, server identity, document
version, and metadata. Conflicts are marked explicitly via
`conflict_reason` — they are never silently guessed.

### 6.4 References fusion

LSP `textDocument/references` is **supplementary only**. Reference
evidence is never auto-persisted as repository edges. It is deduplicated
by `(file, byte_start, byte_end)` and cached with a short TTL.

### 6.5 Staleness binding

Cache keys bind to: `repository_id`, `workspace_id`, `file_path`,
`content_hash`, `file_generation`, `document_version`,
`candidate_range`, `server_identity`. Any mismatch invalidates the
cache entry. The fusion service also checks the IndexStore's current
generation before issuing an LSP request — if the file was modified
after the context was built, the result is marked `lsp-stale`.

### 6.6 Concurrency

Concurrent fusion requests for the same candidate are deduplicated via
`asyncio.Future`. Only one LSP request is sent; all waiters receive the
same result. The cache is thread-safe via `threading.RLock`.

### 6.7 Cache limits

| Limit | Value |
|---|---|
| Max entries | 2048 |
| TTL | 300 seconds |
| Max bytes | 16 MiB |
| Eviction | LRU + TTL + server-identity mismatch |

---

## 7. URI Mapping and Workspace Boundary

`map_lsp_uri_to_workspace_path` enforces strict workspace containment:

- Rejects non-`file:` URIs (`NonFileUriError`)
- Rejects `..` path traversal (`WorkspaceEscapeError`)
- Rejects workspace-external paths (`WorkspaceEscapeError`, code `workspace-external`)
- Rejects paths in other task workspaces (`WorkspaceEscapeError`, code `other-task-workspace`)
- Rejects symlink escapes (`SymlinkEscapeError`)
- Applies percent-decoding (including Unicode)
- Returns a repository-relative POSIX path

The workspace boundary is enforced before any LSP location is converted
to evidence. No workspace-external URI is ever accepted as an internal
target.

---

## 8. Known Limitations

1. **No type inference.** `obj.method()` is `dynamic`, never resolved
   by repository analysis. LSP may promote it via fusion.
2. **No remote dependency resolution.** `import react` is `external`.
   The system never downloads or reads remote package metadata.
3. **No LSP server downloads.** Tests skip if no trusted LSP binary is
   on `PATH`. The system never installs a Language Server.
4. **No LSP process lifecycle redesign.** LSP I/O goes through the
   existing `LspClient` → `ExecutionService.start_managed_process`
   path. No new subprocess path is introduced.
5. **No cross-workspace LSP leakage.** LSP URIs from other task
   workspaces are rejected.
6. **ParseState is process-local.** A process restart loses the
   incremental parse cache (but IndexStore data survives on disk).
7. **LSP fusion is server-side only.** There is no per-tool-call
   toggle; the feature flag is global.

---

## 9. Performance Data (1,015-file fixture)

Hardware: macOS (Apple Silicon). CI does not enforce hard thresholds;
the numbers below are representative, not contractual.

### 9.1 Repository resolution

| Scenario | Time | Affected files |
|---|---|---|
| A. First full resolution | 592.6 ms | 1015 |
| B. No-modification refresh | 69.3 ms | 0 |
| C. Leaf file modify | 63.8 ms | 1 |
| D. Common file modify | 64.6 ms | 20 |
| E. Delete target file | 64.1 ms | 20 |
| F. Full rebuild | 592.0 ms | 1015 |

Ground truth: TP=2847, FP=0, precision=1.0000, eligible=2867,
resolved=2847, coverage=0.9930.

### 9.2 LSP evidence fusion

| Scenario | Time | LSP requests |
|---|---|---|
| Fusion OFF, 100 edges | 28.2 ms (0.28 ms/edge) | 0 |
| Fusion ON, first edge | < 1 ms | 1 |
| Fusion ON, repeated edge (cache hit) | < 1 ms | 0 |
| File modification invalidation | < 1 ms | 1 (stale) |
| LSP timeout fallback | < 100 ms | 1 (timed out) |

---

## 10. Fallback Behavior

| Trigger | Fallback |
|---|---|
| Tree-sitter not installed | Legacy `CodeParser` (regex-based) |
| Tree-sitter parse failure | `parse-failed` status, file skipped |
| LSP not installed | Repository-only resolution |
| LSP timeout | Repository-only result (`lsp-unavailable`) |
| LSP crash | Repository-only result (`lsp-unavailable`) |
| LSP returns external URI | `external` status (`lsp-external`) |
| LSP returns multiple targets | `ambiguous` status (`lsp-ambiguous`) |
| Stale file generation | Repository-only result (`lsp-stale`) |
| Feature flag OFF | Repository-only result (`repository-only`) |

In every fallback case, the fused result is identical to the repository
resolution. LSP evidence is additive — it can only confirm, promote, or
flag conflict; it can never silently override repository resolution.

---

## 11. Security Boundaries

1. **No new subprocess.** All LSP I/O goes through the existing
   `LspClient` → `ExecutionService.start_managed_process` path with
   `trusted_argv`, `network=none`, and workspace binding. No raw
   `subprocess`, `os.system`, or `os.popen` calls in the LSP modules.
2. **No native Tree persistence.** `ParseState` and the native
   `Tree` object are never serialized to disk or SQLite.
3. **No workspace escape.** LSP URIs are strictly contained to the
   active workspace; symlinks are walked and validated.
4. **No unbounded cache.** The LSP evidence cache is bounded by entry
   count, byte budget, and TTL.
5. **No M2 execution bypass.** The M3 intelligence layer does not
   modify the M2 sandbox or execution-safety architecture.
6. **No remote downloads.** The system never downloads Tree-sitter
   grammars, LSP servers, or package metadata.
7. **Stale-generation CAS.** Resolved edges carry a generation counter;
   stale resolutions cannot overwrite newer ones.

---

## 12. Test Coverage

| Test file | Tests | Purpose |
|---|---|---|
| `test_lsp_evidence_fusion.py` | 33 | 30 mandatory Fake LSP scenarios + 3 references tests |
| `test_lsp_uri_mapping.py` | 16 | Workspace boundary, percent decode, symlink escape |
| `test_lsp_positions.py` | 45 | UTF-16 ↔ byte ↔ code-point conversion |
| `test_lsp_evidence_cache.py` | 16 | LRU, TTL, server-identity, invalidation |
| `test_lsp_real_fusion.py` | 1 (skip if no LSP) | Optional real Python LSP E2E |
| `test_lsp_fusion_performance.py` | 4 | 1,015-file benchmark, cache hits, invalidation, timeout |
| `test_m3_closure_matrix.py` | 11 | Six-dialect E2E closure + degradation + provenance |
| `test_tree_sitter_resolution_e2e.py` | 9 | Real Tree-sitter resolution per dialect |
| `test_resolution_performance.py` | 4 | 1,000-file performance + incremental + exact ground truth |

Total M3 tests: 130+ (across LSP fusion, URI, positions, cache, closure
matrix, performance, and E2E).

---

## 13. Configuration Reference

```yaml
coding:
  intelligence:
    lsp_evidence_fusion:
      enabled: false                              # feature flag (default OFF)
      request_timeout_seconds: 5.0                # per-LSP-request timeout
      cache_max_entries: 2048                     # LRU entry cap
      cache_ttl_seconds: 300                      # TTL in seconds
      cache_max_bytes_mib: 16                     # byte budget
```

The feature flag is server-side only. There is no per-tool-call toggle.
When `enabled: false`, all fusion methods return repository-only results
with `depends_on_lsp=False`.
