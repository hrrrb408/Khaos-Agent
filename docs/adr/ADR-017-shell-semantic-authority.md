# ADR-017: Shell Semantic Authority

**状态：** Accepted for M6.1

## Context

`terminal_argv` and `terminal_shell` are different security contracts.  An
argv vector is already tokenized by the caller, while a shell script is a
program whose executable graph can be changed by expansion, control flow,
redirection, callbacks, and nested evaluation.  Classifying a shell string by
`shlex.split()`, regular expressions, or its first executable can therefore
turn an approved read-only label into a different effect.

## Decision

`python/khaos/security/shell_semantics.py` is the non-executing semantic
authority for shell strings.  It emits an immutable AST digest and one of:

- `safe`: every executable node is literal and covered by an argv-aware
  read-only policy;
- `semantic-unknown`: the script is syntactically representable but its final
  executable graph is not proven literal; approval is required;
- `blocked`: a literal or nested executable is in the hard-deny set.

Brace/glob/tilde/parameter/command/arithmetic/process substitutions,
heredocs/here-strings, redirections, subshells, compound syntax, environment
assignments, shell evaluators, and executable callback options are never
read-only shortcuts.  `terminal_argv` uses `analyze_argv()` and does not apply
shell expansion semantics.  Shell approval resources bind both the original
script digest and the semantic AST digest/status.

Unknown syntax is an approval requirement, not a compatibility fallback.  The
parser never invokes a shell and does not claim that `bash -n` syntax validity
proves effect safety.

## Consequences

Read-only convenience approval is available only to a proven literal graph.
Persistent shell grants remain exact-script grants and cannot make an unknown
script eligible for the read-only shortcut.  The conservative policy may ask
for approval for legitimate advanced shell syntax, which is intentional.

