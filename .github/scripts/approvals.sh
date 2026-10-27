#!/usr/bin/env bash
# Separation of duties for a protected environment's review:
#
#     GH_TOKEN=... [SOURCE_SHA=<commit>] [ALLOW_SELF_APPROVAL=...] \
#       bash .github/scripts/approvals.sh <environment>
#
# Reads the review of <environment> in this run back from GitHub and decides
# whether it carries the deployment.
#
# The rule: whoever STARTED this run, and whoever RE-RAN it, cannot be its
# approver — you may not approve the deployment you put in motion. That is the
# whole exclusion set. Any other valid reviewer may approve, including someone
# who authored part of the change: authorship is not self-approval, and the
# environment's own required-reviewers list is the authority on who is allowed
# to review at all.
#
# This replaced a stricter set that also excluded every author of the change
# and of its pull requests. In a repository with two reviewers and a merge
# train that one person drives, that set excluded both accounts — the starter
# AND the author — and the pipeline then failed with "no eligible approver
# exists" while GitHub had accepted a perfectly valid second-person review.
# The check must not be able to reach that state: if the environment lists
# someone who is not the starter, that person can approve.
#
# Writes started=, approved= (JSON arrays of logins) and detail= to
# $GITHUB_OUTPUT; exits 1 when nobody approved, when every approval came from
# the starter or a re-runner, or when a GitHub read this decision depends on
# fails.
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

# Who is barred: the starter, plus the re-runner on a later attempt. Authorship
# is deliberately NOT part of this — a contributor may review the release of a
# change they wrote; what they may not do is approve the run they started.
excluded=$started
approved=$(jq -c --arg e "$environment" \
  '[.[] | select(.state == "approved" and any(.environments[]?; .name == $e)) | .user.login] | unique' <<<"$approvals")
# self: approvals from someone excluded. eligible: approvals from someone who
# did none of those — one of these has to exist for the review to count.
self=$(jq -rn --argjson a "$approved" --argjson e "$excluded" '($a - ($a - $e)) | join(", ")')
eligible=$(jq -rn --argjson a "$approved" --argjson e "$excluded" '($a - $e) | join(", ")')
{ echo "started=$started"; echo "approved=$approved"; } >> "$GITHUB_OUTPUT"

summary=$(jq -rn --argjson s "$started" --argjson ap "$approved" \
  '"started by " + ($s | join(", ")) + ", approved by " + ($ap | join(", "))')

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
    detail="no eligible ${environment} approver: every reviewer of this environment (${reviewers}) started or re-ran this run, and the starter of a deployment may not approve it — add a reviewer who did not start it"
    if [ "$admin_bypass" = "true" ]; then
      detail="${detail}; the environment does allow repository admins to bypass its review, so an admin approval can still carry it"
    fi
    detail="${detail}, or opt into the documented single-operator exception (set the ALLOW_SELF_APPROVAL repository variable for a run the pipeline starts; a manual run can pass allow-self-approval, honoured only for repository admins)"
  else
    detail="${environment} was approved only by ${self}, who started or re-ran this run — someone who did not start it must approve"
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
