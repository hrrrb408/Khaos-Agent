#!/usr/bin/env bash
set -euo pipefail

repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
out_dir="${1:-ruleset-audit}"
expected_file="$(dirname "$0")/github-main-ruleset.json"
mkdir -p "$out_dir"

gh api "repos/$repo/rulesets?includes_parents=true" --paginate > "$out_dir/rulesets.json"
jq -e 'type == "array" and length > 0' "$out_dir/rulesets.json" >/dev/null

: > "$out_dir/ruleset-details.jsonl"
jq -r '.[].id' "$out_dir/rulesets.json" | while read -r id; do
  gh api "repos/$repo/rulesets/$id" >> "$out_dir/ruleset-details.jsonl"
done

jq -s -e --slurpfile expected "$expected_file" '
  ($expected[0].rules[] |
    select(.type == "required_status_checks") |
    .parameters.required_status_checks |
    map(.context) | sort) as $required |
  any(.[];
    .enforcement == "active" and
    .target == "branch" and
    any(.conditions.ref_name.include[]?; . == "~DEFAULT_BRANCH") and
    any(.rules[]?; .type == "deletion") and
    any(.rules[]?; .type == "non_fast_forward") and
    any(.rules[]?; .type == "pull_request" and
      (.parameters.required_approving_review_count // 0) == 0 and
      .parameters.require_code_owner_review == false and
      .parameters.dismiss_stale_reviews_on_push == false and
      .parameters.require_last_push_approval == false and
      .parameters.required_review_thread_resolution == true) and
    any(.rules[]?; .type == "required_status_checks" and
      .parameters.do_not_enforce_on_create == false and
      (.parameters.strict_required_status_checks_policy == true) and
      ((.parameters.required_status_checks | map(.context) | sort) == $required))
  )
' "$out_dir/ruleset-details.jsonl" >/dev/null

printf '%s\n' "active single-maintainer ruleset enforces up-to-date checks, resolved review threads, and force-push/deletion protection"
