"""
graders.py — Deterministic IAM policy simulator and task graders.

Simulator scope (exact spec, no scope creep):
  1. Exact ARN match          — "arn:aws:s3:::bucket/key" == "arn:aws:s3:::bucket/key"
  2. Trailing-* wildcard      — "arn:aws:s3:::bucket/*" matches "arn:aws:s3:::bucket/anything"
  3. Single-char ? wildcard   — "arn:aws:s3:::bucket/fil?" matches "arn:aws:s3:::bucket/file"
  4. Action prefix match      — "s3:Get*" matches "s3:GetObject", "s3:GetBucketAcl"
  5. Bare "*" resource/action — matches everything
  6. NO Condition evaluation  — out of scope by design
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# IAM Policy Simulator (scoped)
# ---------------------------------------------------------------------------

class IAMSimulatorError(Exception):
    """Raised for malformed policy JSON."""


def _parse_policy(policy_json: str) -> Dict[str, Any]:
    """Parse and lightly validate policy JSON. Raises IAMSimulatorError on failure."""
    try:
        policy = json.loads(policy_json)
    except json.JSONDecodeError as exc:
        raise IAMSimulatorError(f"Invalid JSON: {exc}") from exc

    if not isinstance(policy, dict):
        raise IAMSimulatorError("Policy must be a JSON object.")
    if "Statement" not in policy:
        raise IAMSimulatorError("Policy must contain a 'Statement' key.")
    if not isinstance(policy["Statement"], list):
        raise IAMSimulatorError("'Statement' must be a list.")
    return policy


def _matches(pattern: str, value: str) -> bool:
    """
    Match a single IAM pattern against a value.
    Handles: exact, trailing *, single-char ?, action-prefix (s3:Get*).
    Both comparison are case-insensitive for actions; case-sensitive for ARNs.
    """
    if pattern == "*":
        return True
    # fnmatch covers *, ?, [seq] — we only advertise * and ? but fnmatch is safe here
    return fnmatch.fnmatchcase(value, pattern)


def _action_matches(pattern: str, action: str) -> bool:
    """Case-insensitive action matching."""
    return _matches(pattern.lower(), action.lower())


def _resource_matches(pattern: str, resource: str) -> bool:
    """Case-sensitive ARN matching (AWS ARNs are case-sensitive for most parts)."""
    return _matches(pattern, resource)


def _normalize_to_list(value: Any) -> List[str]:
    """IAM allows Action/Resource as string or list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def simulate_api_call(policy_json: str, action: str, resource: str) -> Tuple[bool, str]:
    """
    Simulate whether a policy allows (action, resource).

    Returns:
        (allowed: bool, reason: str)

    Logic mirrors AWS IAM evaluation:
      - Default DENY
      - If any Allow statement matches → ALLOW (unless an explicit Deny overrides)
      - Explicit Deny always wins
    """
    try:
        policy = _parse_policy(policy_json)
    except IAMSimulatorError as exc:
        return False, f"POLICY_PARSE_ERROR: {exc}"

    explicit_deny = False
    explicit_allow = False

    for stmt in policy["Statement"]:
        effect = stmt.get("Effect", "Allow")
        actions = _normalize_to_list(stmt.get("Action", []))
        resources = _normalize_to_list(stmt.get("Resource", []))

        # Principal is ignored in permission policies; only relevant in trust policies
        # (handled separately in hard grader)

        action_match = any(_action_matches(a, action) for a in actions)
        resource_match = any(_resource_matches(r, resource) for r in resources)

        if action_match and resource_match:
            if effect == "Deny":
                explicit_deny = True
            elif effect == "Allow":
                explicit_allow = True

    if explicit_deny:
        return False, f"EXPLICIT_DENY: {action} on {resource}"
    if explicit_allow:
        return True, f"ALLOW: {action} on {resource}"
    return False, f"IMPLICIT_DENY: {action} on {resource}"


def count_wildcards(policy_json: str) -> int:
    """Count wildcard occurrences in Action and Resource fields of all statements."""
    try:
        policy = _parse_policy(policy_json)
    except IAMSimulatorError:
        return 0

    count = 0
    for stmt in policy.get("Statement", []):
        for field in ("Action", "Resource"):
            values = _normalize_to_list(stmt.get(field, []))
            for v in values:
                if "*" in v or "?" in v:
                    count += 1
    return count


# ---------------------------------------------------------------------------
# Analyze helper (used by AnalyzePolicy action)
# ---------------------------------------------------------------------------

@dataclass
class AnalysisResult:
    missing_actions: List[str]      # audit log calls the current policy DENIES
    allowed_wildcards: List[str]    # wildcard patterns still present
    wildcard_count: int
    coverage_ratio: float           # fraction of audit log calls currently allowed
    feedback: str


def analyze_policy(policy_json: str, audit_log: List[str]) -> AnalysisResult:
    """
    Diff the policy against the audit log.
    Returns which required calls are blocked and which wildcards remain.
    """
    missing: List[str] = []
    covered = 0

    for entry in audit_log:
        # entry format: "service:Action on ARN"
        parts = entry.split(" on ", 1)
        if len(parts) != 2:
            continue
        action, resource = parts[0].strip(), parts[1].strip()
        allowed, _ = simulate_api_call(policy_json, action, resource)
        if allowed:
            covered += 1
        else:
            missing.append(entry)

    wildcards: List[str] = []
    try:
        policy = _parse_policy(policy_json)
        for stmt in policy.get("Statement", []):
            for field in ("Action", "Resource"):
                values = _normalize_to_list(stmt.get(field, []))
                for v in values:
                    if "*" in v or "?" in v:
                        wildcards.append(f"{field}: {v}")
    except IAMSimulatorError:
        pass

    total = len(audit_log)
    coverage = covered / total if total > 0 else 0.0

    lines = [
        f"Coverage: {covered}/{total} audit-log calls allowed ({coverage:.0%}).",
    ]
    if missing:
        lines.append("BLOCKED (required) calls:")
        lines.extend(f"  - {m}" for m in missing)
    else:
        lines.append("All required calls are currently ALLOWED.")
    if wildcards:
        lines.append("Remaining wildcards:")
        lines.extend(f"  - {w}" for w in wildcards)
    else:
        lines.append("No wildcards remaining.")

    return AnalysisResult(
        missing_actions=missing,
        allowed_wildcards=wildcards,
        wildcard_count=len(wildcards),
        coverage_ratio=coverage,
        feedback="\n".join(lines),
    )


# ---------------------------------------------------------------------------
# GRADER — EASY (S3 Bucket Lockdown)
# ---------------------------------------------------------------------------

# The 4 simulation calls used by the easy grader
_EASY_TEST_SUITE = [
    # Must ALLOW
    ("s3:GetObject", "arn:aws:s3:::report-bucket/q1-report.csv", True),
    ("s3:GetObject", "arn:aws:s3:::report-bucket/q2-report.csv", True),
    ("s3:GetObject", "arn:aws:s3:::report-bucket/subdir/file.txt", True),
    # Must DENY
    ("s3:DeleteObject", "arn:aws:s3:::report-bucket/q1-report.csv", False),
    ("s3:PutObject", "arn:aws:s3:::report-bucket/new.csv", False),
    ("s3:GetObject", "arn:aws:s3:::other-bucket/secret.txt", False),
]


@dataclass
class GraderResult:
    score: float                    # 0.0 – 1.0
    passed: int
    total: int
    feedback: str
    details: List[str]


def grade_easy(policy_json: str) -> GraderResult:
    """
    Deterministic grader for Task 1 (S3 Bucket Lockdown).

    Test suite: 3 must-allow + 3 must-deny = 6 checks.
    Score = passed / 6.
    """
    try:
        _parse_policy(policy_json)
    except IAMSimulatorError as exc:
        return GraderResult(
            score=0.0, passed=0, total=len(_EASY_TEST_SUITE),
            feedback=f"POLICY_PARSE_ERROR: {exc}", details=[]
        )

    passed = 0
    details: List[str] = []

    for action, resource, expected_allow in _EASY_TEST_SUITE:
        allowed, reason = simulate_api_call(policy_json, action, resource)
        ok = (allowed == expected_allow)
        status = "PASS" if ok else "FAIL"
        expectation = "ALLOW" if expected_allow else "DENY"
        details.append(f"[{status}] Expected {expectation}: {action} on {resource} — {reason}")
        if ok:
            passed += 1

    score = round(passed / len(_EASY_TEST_SUITE), 4)
    feedback = (
        f"Easy grader: {passed}/{len(_EASY_TEST_SUITE)} checks passed. Score={score:.4f}"
    )
    return GraderResult(score=score, passed=passed, total=len(_EASY_TEST_SUITE),
                        feedback=feedback, details=details)


# ---------------------------------------------------------------------------
# GRADER — MEDIUM (DynamoDB + SQS)
# ---------------------------------------------------------------------------

_MEDIUM_TEST_SUITE = [
    # Must ALLOW — DynamoDB
    ("dynamodb:PutItem",    "arn:aws:dynamodb:us-east-1:123456789012:table/orders", True),
    ("dynamodb:GetItem",    "arn:aws:dynamodb:us-east-1:123456789012:table/orders", True),
    ("dynamodb:UpdateItem", "arn:aws:dynamodb:us-east-1:123456789012:table/orders", True),
    ("dynamodb:Query",      "arn:aws:dynamodb:us-east-1:123456789012:table/orders", True),
    # Must ALLOW — SQS
    ("sqs:SendMessage",    "arn:aws:sqs:us-east-1:123456789012:order-queue", True),
    ("sqs:ReceiveMessage", "arn:aws:sqs:us-east-1:123456789012:order-queue", True),
    ("sqs:DeleteMessage",  "arn:aws:sqs:us-east-1:123456789012:order-queue", True),
    # Must DENY — actions not in audit log
    ("dynamodb:DeleteTable", "arn:aws:dynamodb:us-east-1:123456789012:table/orders", False),
    ("sqs:DeleteQueue",      "arn:aws:sqs:us-east-1:123456789012:order-queue", False),
    # Must DENY — correct action, wrong resource
    ("dynamodb:PutItem", "arn:aws:dynamodb:us-east-1:123456789012:table/other-table", False),
]


def grade_medium(policy_json: str) -> GraderResult:
    """
    Deterministic grader for Task 2 (DynamoDB + SQS).

    Test suite: 7 must-allow + 3 must-deny = 10 checks.
    Score = passed / 10.
    """
    try:
        _parse_policy(policy_json)
    except IAMSimulatorError as exc:
        return GraderResult(
            score=0.0, passed=0, total=len(_MEDIUM_TEST_SUITE),
            feedback=f"POLICY_PARSE_ERROR: {exc}", details=[]
        )

    passed = 0
    details: List[str] = []

    for action, resource, expected_allow in _MEDIUM_TEST_SUITE:
        allowed, reason = simulate_api_call(policy_json, action, resource)
        ok = (allowed == expected_allow)
        status = "PASS" if ok else "FAIL"
        expectation = "ALLOW" if expected_allow else "DENY"
        details.append(f"[{status}] Expected {expectation}: {action} on {resource} — {reason}")
        if ok:
            passed += 1

    score = round(passed / len(_MEDIUM_TEST_SUITE), 4)
    feedback = (
        f"Medium grader: {passed}/{len(_MEDIUM_TEST_SUITE)} checks passed. Score={score:.4f}"
    )
    return GraderResult(score=score, passed=passed, total=len(_MEDIUM_TEST_SUITE),
                        feedback=feedback, details=details)


# ---------------------------------------------------------------------------
# GRADER — HARD (Cross-Account Trust Policy)
# ---------------------------------------------------------------------------
#
# Trust policies use Principal instead of a subject, and sts:AssumeRole is the
# only action. We evaluate: does the trust policy allow the correct ARN and
# block all others? No simulation needed — pure JSON principal matching.
#
# Authorised principal (from security memo):
#   arn:aws:iam::987654321098:role/DeploymentPipeline
#
# Test suite:
#   ALLOW  — arn:aws:iam::987654321098:role/DeploymentPipeline
#   DENY   — arn:aws:iam::111111111111:role/AttackerRole
#   DENY   — arn:aws:iam::987654321098:role/OtherRole  (right account, wrong role)
#   DENY   — * (bare wildcard)
#   DENY   — arn:aws:iam::*:role/DeploymentPipeline  (wildcard account)

_AUTHORISED_PRINCIPAL = "arn:aws:iam::987654321098:role/DeploymentPipeline"

_HARD_PRINCIPAL_SUITE = [
    (_AUTHORISED_PRINCIPAL,                             True),   # authorised — must ALLOW
    ("arn:aws:iam::111111111111:role/AttackerRole",     False),  # different account — must DENY
    ("arn:aws:iam::987654321098:role/OtherRole",        False),  # right account, wrong role
    ("*",                                               False),  # bare wildcard — must DENY
    ("arn:aws:iam::*:role/DeploymentPipeline",          False),  # wildcard account — must DENY
]


def _trust_policy_allows_principal(policy_json: str, principal_arn: str) -> Tuple[bool, str]:
    """
    Evaluate whether a trust policy's Principal field allows the given ARN.
    Handles: string, list, {"AWS": ...}, {"Service": ...} forms.
    The authorised ARN must be an EXACT match (no wildcards accepted for security).
    """
    try:
        policy = _parse_policy(policy_json)
    except IAMSimulatorError as exc:
        return False, f"PARSE_ERROR: {exc}"

    for stmt in policy.get("Statement", []):
        effect = stmt.get("Effect", "Allow")
        action = stmt.get("Action", "")
        principal_field = stmt.get("Principal", None)

        # Only care about sts:AssumeRole statements
        actions = _normalize_to_list(action)
        if not any(_action_matches(a, "sts:AssumeRole") for a in actions):
            continue

        # Collect all principal strings
        principals: List[str] = []
        if principal_field == "*":
            principals = ["*"]
        elif isinstance(principal_field, str):
            principals = [principal_field]
        elif isinstance(principal_field, list):
            principals = [str(p) for p in principal_field]
        elif isinstance(principal_field, dict):
            for key in ("AWS", "Service", "Federated"):
                val = principal_field.get(key, [])
                principals.extend(_normalize_to_list(val))

        for p in principals:
            if p == "*":
                # bare wildcard matches everything — check effect
                if effect == "Allow":
                    return True, "ALLOW via wildcard Principal '*'"
                else:
                    return False, "DENY via wildcard Principal '*'"
            # Exact match only for security — no fnmatch on principal ARNs
            if p == principal_arn:
                if effect == "Allow":
                    return True, f"ALLOW: Principal {p} explicitly allowed"
                else:
                    return False, f"DENY: Principal {p} explicitly denied"
            # Wildcard ARN (e.g. arn:aws:iam::*:role/X) — NEVER allow
            if "*" in p or "?" in p:
                if effect == "Allow":
                    # This is a wildcard principal in an Allow — treat as overly permissive
                    # Check if it would match our test principal (security concern)
                    if fnmatch.fnmatchcase(principal_arn, p):
                        # Matches via wildcard: we FAIL this — not exact enough
                        return True, f"ALLOW via wildcard pattern {p} (INSECURE)"
                # continue checking other principals

    return False, f"IMPLICIT_DENY: No Allow statement covers {principal_arn}"


def grade_hard(policy_json: str) -> GraderResult:
    """
    Deterministic grader for Task 3 (Cross-Account Trust Policy Lockdown).

    Test suite: 5 principal checks (1 allow + 4 deny).
    Scoring:
      - Authorised principal allowed  : 0.40 pts (core requirement)
      - Each of 4 blocked principals  : 0.15 pts each = 0.60 pts
      Total maximum                   : 1.00

    A policy that passes the allow but keeps Principal:"*" scores 0.40 only.
    A policy that locks down everything scores 1.00.
    """
    try:
        _parse_policy(policy_json)
    except IAMSimulatorError as exc:
        return GraderResult(
            score=0.0, passed=0, total=len(_HARD_PRINCIPAL_SUITE),
            feedback=f"POLICY_PARSE_ERROR: {exc}", details=[]
        )

    weights = [0.40, 0.15, 0.15, 0.15, 0.15]  # must sum to 1.0
    passed = 0
    score_sum = 0.0
    details: List[str] = []

    for (principal, expected_allow), weight in zip(_HARD_PRINCIPAL_SUITE, weights):
        allowed, reason = _trust_policy_allows_principal(policy_json, principal)
        ok = (allowed == expected_allow)
        status = "PASS" if ok else "FAIL"
        expectation = "ALLOW" if expected_allow else "DENY"
        details.append(
            f"[{status}] ({weight:.2f}pts) Expected {expectation} for principal "
            f"'{principal}' — {reason}"
        )
        if ok:
            passed += 1
            score_sum += weight

    score = round(min(score_sum, 1.0), 4)
    feedback = (
        f"Hard grader: {passed}/{len(_HARD_PRINCIPAL_SUITE)} checks passed. Score={score:.4f}"
    )
    return GraderResult(score=score, passed=passed, total=len(_HARD_PRINCIPAL_SUITE),
                        feedback=feedback, details=details)


# ---------------------------------------------------------------------------
# Unified grader dispatcher
# ---------------------------------------------------------------------------

def grade(task_id: str, policy_json: str) -> GraderResult:
    """Run the correct grader for the given task_id."""
    if task_id == "easy":
        return grade_easy(policy_json)
    elif task_id == "medium":
        return grade_medium(policy_json)
    elif task_id == "hard":
        return grade_hard(policy_json)
    else:
        raise ValueError(f"Unknown task_id: '{task_id}'")
