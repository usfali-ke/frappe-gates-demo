#!/usr/bin/env bash
# Separation of duties for a protected environment's review:
#
#     GH_TOKEN=... [SOURCE_SHA=<commit>] [ALLOW_SELF_APPROVAL=...] \
#       bash .github/scripts/approvals.sh <environment>
#
# Reads the review of <environment> in this run back from GitHub. Whoever
# started the run — or re-ran it — can't be its approver, and neither can
# whoever authored the change being released or opened its pull request: at
# least one approval must come from someone who did none of those.
# Writes started=, authors= and approved= (JSON arrays of logins) and
# detail= to $GITHUB_OUTPUT; exits 1 when nobody approved, when every
# approval came from someone excluded, or when a GitHub read this decision
# depends on fails.
#
# Three things used to make this reject the only person who could approve:
#
#   * the change's "author" was read from the commit on main, which for a
#     merged pull request is a merge commit GitHub attributes to whoever
#     merged it — the releaser, not the author — barring them from
#     approving the merge they made;
#   * triggering_actor was excluded even on the first attempt, where a
#     run the pipeline starts has github-actions as its actor and
#     triggering_actor is only the human whose push or merge set that
#     pipeline going — a case the change check already covers;
#   * every approval being excluded was reported as that approver's fault,
#     even when the environment left nobody able to approve.
#
# So the change is resolved from the pull request (its author and its
# commits' authors), triggering_actor is excluded only on a re-run, and the
# message separates "the wrong person approved" from "nobody could".
set -euo pipefail

environment=$1

# gh api with retries. The author lookups decide who may approve, so a failed
# read has to stop the check rather than quietly shrink the excluded set.
gh_api() {
  local path=$1 out i
  for i in 1 2 3; do
    if out=$(gh api "$path" 2>/dev/null); then printf '%s' "$out"; return 0; fi
    sleep 2
  done
  return 1
}

fail_hard() {
  echo "detail=$1" >> "$GITHUB_OUTPUT"
  echo "::error::$1"
  exit 1
}

run=$(gh_api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}") \
  || fail_hard "cannot read this run from GitHub: the segregation-of-duties check could not run"
approvals=$(gh_api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/approvals") \
  || fail_hard "cannot read this run's environment approvals from GitHub: the segregation-of-duties check could not run"

# On a re-run, triggering_actor is whoever re-ran this attempt; on the first
# attempt it is not the run's starter (the pipeline's own dispatch is the
# actor), so it is not excluded here.
started=$(jq -c '[.actor.login, (if (.run_attempt // 1) > 1 then .triggering_actor.login else empty end)]
                 | map(select(.)) | unique' <<<"$run")

authors='[]'
if [ -n "${SOURCE_SHA:-}" ]; then
  commit=$(gh_api "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}") \
    || fail_hard "cannot read commit ${SOURCE_SHA:0:12} from GitHub: who authored the change can't be decided"
  prs=$(gh_api "repos/${GITHUB_REPOSITORY}/commits/${SOURCE_SHA}/pulls") \
    || fail_hard "cannot read the pull requests containing ${SOURCE_SHA:0:12} from GitHub: who authored the change can't be decided"
  pr_authors='[]'
  for n in $(jq -r '.[]?.number' <<<"$prs"); do
    cs=$(gh_api "repos/${GITHUB_REPOSITORY}/pulls/${n}/commits") \
      || fail_hard "cannot read the commits of pull request #${n} from GitHub: who authored the change can't be decided"
    pr_authors=$(jq -nc --argjson a "$pr_authors" --argjson c "$cs" '$a + [$c[]?.author.login]')
  done
  # web-flow commits GitHub's own merges; bots can't approve anyway.
  authors=$(jq -nc --argjson c "$commit" --argjson p "$prs" --argjson pa "$pr_authors" \
    '((if ($p | length) > 0 then [$p[]?.user.login] else [$c.author.login] end) + $pa)
     | map(select(. and . != "web-flow" and (endswith("[bot]") | not))) | unique')
fi

excluded=$(jq -nc --argjson s "$started" --argjson a "$authors" '$s + $a | unique')
approved=$(jq -c --arg e "$environment" \
  '[.[] | select(.state == "approved" and any(.environments[]?; .name == $e)) | .user.login] | unique' <<<"$approvals")
# self: approvals from someone excluded. eligible: approvals from someone who
# did none of those — one of these has to exist for the review to count.
self=$(jq -rn --argjson a "$approved" --argjson e "$excluded" '($a - ($a - $e)) | join(", ")')
eligible=$(jq -rn --argjson a "$approved" --argjson e "$excluded" '($a - $e) | join(", ")')
{ echo "started=$started"; echo "authors=$authors"; echo "approved=$approved"; } >> "$GITHUB_OUTPUT"

summary=$(jq -rn --argjson s "$started" --argjson a "$authors" --argjson ap "$approved" \
  '"started by " + ($s | join(", "))
   + (if ($a | length) > 0 then ", change by " + ($a | join(", ")) else "" end)
   + ", approved by " + ($ap | join(", "))')

if [ "$approved" = "[]" ]; then
  detail="no ${environment} approval recorded for this run"
elif [ -n "$eligible" ]; then
  detail="$summary"
  echo "detail=$detail" >> "$GITHUB_OUTPUT"
  echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
  exit 0
else
  # Every approval came from someone excluded. Report which, and whether the
  # environment has anybody left who could approve at all.
  env_json=$(gh_api "repos/${GITHUB_REPOSITORY}/environments/${environment}" || echo '{}')
  reviewers=$(jq -c '[.protection_rules[]? | select(.type == "required_reviewers") | .reviewers[]?
                      | (.reviewer.login // .reviewer.name)] | map(select(.)) | unique' <<<"$env_json")
  reviewers=${reviewers:-[]}
  admin_bypass=$(jq -r '.can_admins_bypass // false' <<<"$env_json")
  remaining=$(jq -cn --argjson r "$reviewers" --argjson e "$excluded" '$r - $e')
  if [ "$reviewers" != "[]" ] && [ "$remaining" = "[]" ]; then
    detail="no eligible ${environment} approver exists: every reviewer of this environment (${reviewers}) is excluded — the run's starter, a re-runner, or the change's authors — so no listed reviewer could approve"
    if [ "$admin_bypass" = "true" ]; then
      detail="${detail}; the environment does allow repository admins to bypass its review, so an admin approval can still carry it"
    fi
    detail="${detail}. Add a reviewer who did none of those, or opt into the documented single-operator exception (set the ALLOW_SELF_APPROVAL repository variable for a run the pipeline starts; a manual run can pass allow-self-approval, honoured only for repository admins)"
  else
    detail="${environment} approved only by ${self}, who started or re-ran this run or authored the change — someone who did neither must approve"
  fi
  # Documented single-operator exception: where one account starts the pipeline
  # and the other authors the change, the doc's strict rule leaves no eligible
  # approver. The waiver is admin-level — honoured only when the account behind
  # this attempt is a repository admin, or the run was started by the pipeline
  # itself, whose dispatch can only carry the value from the ALLOW_SELF_APPROVAL
  # repository variable that only an admin can set. It is written into the
  # verdict detail, which the dashboard records verbatim, so it stays visible.
  waiver_actor=$(jq -r '.triggering_actor.login // .actor.login // empty' <<<"$run")
  waiver=false
  case "${ALLOW_SELF_APPROVAL:-}" in
    true|1)
      if [ "$waiver_actor" = "github-actions[bot]" ]; then
        waiver=true
      else
        perm=$(gh_api "repos/${GITHUB_REPOSITORY}/collaborators/${waiver_actor}/permission" 2>/dev/null \
          | jq -r '.permission // "none"' || echo none)
        if [ "$perm" = "admin" ]; then
          waiver=true
        else
          detail="the allow-self-approval waiver was requested but ${waiver_actor} (${perm}) is not a repository admin, so it is refused — ${detail}"
        fi
      fi ;;
  esac
  if [ "$waiver" = "true" ]; then
    detail="SEGREGATION-OF-DUTIES EXCEPTION (single-operator mode): ${summary} — exclusion waived by ALLOW_SELF_APPROVAL (${waiver_actor})"
    echo "detail=$detail" >> "$GITHUB_OUTPUT"
    echo "::warning::$detail"
    echo "$detail" | tee -a "$GITHUB_STEP_SUMMARY"
    exit 0
  fi
fi
echo "detail=$detail" >> "$GITHUB_OUTPUT"
echo "::error::$detail"
exit 1
