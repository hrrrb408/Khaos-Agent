# Shell Semantic Threat Model (M6.1)

## Protected property

An approval or read-only execution profile must describe the complete
executable graph that will run.  Model-controlled shell text must not gain a
different executable, file effect, or callback through shell interpretation
after the decision.

## Attack paths

| Input feature | Before | M6.1 boundary | Postcondition |
| --- | --- | --- | --- |
| glob/brace/tilde expansion | executable/path set changes after split | AST feature `glob-expansion`, `brace-expansion`, or `tilde-expansion` | `semantic-unknown`, approval required |
| `$VAR`, `${...}`, `$()` and backticks | executable graph depends on runtime state | expansion node is retained in AST summary | never read-only |
| `<(...)`, `>(...)`, heredoc, here-string, redirection | hidden process or filesystem effect | redirection/process/heredoc feature | never read-only |
| `eval`, `source`, nested shell, `find -exec`, `rg --pre` | callback executable is not the first argv word | callback feature and command-specific policy | never read-only |
| blocked command in nested substitution | dangerous executable hidden in syntax | nested AST is recursively inspected | hard blocked |
| argv argument containing `$()` or glob text | false shell expansion in argv contract | direct argv parser treats each string as literal | no shell expansion |

## Evidence

- `python/khaos/security/shell_semantics.py` emits canonical AST and SHA-256
  semantic digest without executing input.
- `python/tests/security/test_shell_semantics.py` covers adversarial syntax and
  a syntax-only Bash differential check.
- `python/tests/tools/test_terminal_tools.py` and
  `python/tests/permissions/test_authorization_resource.py` cover the runtime
  and approval-resource integration.

