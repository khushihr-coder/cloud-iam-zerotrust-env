"""
tasks.py — Task definitions for Cloud-IAM-ZeroTrust-Env.

Each task is a dataclass with:
  - id, name, difficulty, description
  - initial_policy: the over-permissive starting policy (JSON string)
  - audit_log: list of "service:Action on ARN" strings the app actually called
  - security_memo: (hard task only) plain-text brief for the agent
  - max_steps
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Task:
    id: str
    name: str
    difficulty: str
    description: str
    initial_policy: str          # JSON string
    audit_log: List[str]
    max_steps: int
    security_memo: Optional[str] = None   # Used in hard task


# ---------------------------------------------------------------------------
# TASK 1 — EASY: S3 Bucket Lockdown
# ---------------------------------------------------------------------------

_EASY_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "S3FullAccess",
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }
    ]
}, indent=2)

_EASY_AUDIT_LOG = [
    "s3:GetObject on arn:aws:s3:::report-bucket/q1-report.csv",
    "s3:GetObject on arn:aws:s3:::report-bucket/q2-report.csv",
]

TASK_EASY = Task(
    id="easy",
    name="S3 Bucket Lockdown",
    difficulty="easy",
    description=(
        "The deployed application has been granted s3:* on all resources. "
        "Security audit shows it only ever reads objects from the 'report-bucket' S3 bucket. "
        "Rewrite the policy to allow ONLY s3:GetObject on "
        "arn:aws:s3:::report-bucket/* and deny everything else."
    ),
    initial_policy=_EASY_POLICY,
    audit_log=_EASY_AUDIT_LOG,
    max_steps=6,
)


# ---------------------------------------------------------------------------
# TASK 2 — MEDIUM: Cross-Service Least Privilege (DynamoDB + SQS)
# ---------------------------------------------------------------------------

_MEDIUM_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DynamoFullAccess",
            "Effect": "Allow",
            "Action": "dynamodb:*",
            "Resource": "*"
        },
        {
            "Sid": "SQSFullAccess",
            "Effect": "Allow",
            "Action": "sqs:*",
            "Resource": "*"
        }
    ]
}, indent=2)

_MEDIUM_AUDIT_LOG = [
    "dynamodb:PutItem on arn:aws:dynamodb:us-east-1:123456789012:table/orders",
    "dynamodb:GetItem on arn:aws:dynamodb:us-east-1:123456789012:table/orders",
    "dynamodb:UpdateItem on arn:aws:dynamodb:us-east-1:123456789012:table/orders",
    "dynamodb:Query on arn:aws:dynamodb:us-east-1:123456789012:table/orders",
    "sqs:SendMessage on arn:aws:sqs:us-east-1:123456789012:order-queue",
    "sqs:ReceiveMessage on arn:aws:sqs:us-east-1:123456789012:order-queue",
    "sqs:DeleteMessage on arn:aws:sqs:us-east-1:123456789012:order-queue",
]

TASK_MEDIUM = Task(
    id="medium",
    name="Cross-Service Least Privilege (DynamoDB + SQS)",
    difficulty="medium",
    description=(
        "The application has been granted dynamodb:* and sqs:* on all resources. "
        "The audit log shows exactly 4 DynamoDB actions on the 'orders' table and "
        "3 SQS actions on the 'order-queue'. "
        "Rewrite the policy to allow ONLY those specific actions on those specific ARNs. "
        "No wildcards in actions or resources. The grader runs 10 simulated API calls."
    ),
    initial_policy=_MEDIUM_POLICY,
    audit_log=_MEDIUM_AUDIT_LOG,
    max_steps=8,
)


# ---------------------------------------------------------------------------
# TASK 3 — HARD: Cross-Account Trust Policy Lockdown
# ---------------------------------------------------------------------------

_HARD_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAnyoneToAssume",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "sts:AssumeRole",
            "Resource": "*"
        }
    ]
}, indent=2)

_HARD_AUDIT_LOG = [
    "sts:AssumeRole from arn:aws:iam::987654321098:role/DeploymentPipeline",
]

_HARD_SECURITY_MEMO = """
SECURITY MEMO — Ref: SEC-2024-041
Date: 2024-01-15
Classification: Internal

The cross-account trust policy for role arn:aws:iam::123456789012:role/ProdDeployRole
is currently open to ALL principals, creating a critical confused-deputy vulnerability.

Authorised External Principal:
  Account ID : 987654321098
  Role Name  : DeploymentPipeline
  Full ARN   : arn:aws:iam::987654321098:role/DeploymentPipeline

Required Permission:
  Action     : sts:AssumeRole

Action Required:
  1. Replace Principal: "*" with the exact authorised ARN above.
  2. Remove the wildcard Resource; trust policies do not use Resource.
  3. No other principals may be listed.

Any policy that allows principals outside account 987654321098 is a FAIL.
"""

TASK_HARD = Task(
    id="hard",
    name="Cross-Account Trust Policy Lockdown",
    difficulty="hard",
    description=(
        "A privileged IAM role has a trust policy that allows ANY principal "
        "to assume it — a textbook confused-deputy attack vector. "
        "A security memo specifies exactly which external account ID and role "
        "are authorised. Rewrite the trust policy Principal to the exact ARN "
        "and remove all wildcards. The grader tests both allowed and blocked principals."
    ),
    initial_policy=_HARD_POLICY,
    audit_log=_HARD_AUDIT_LOG,
    max_steps=10,
    security_memo=_HARD_SECURITY_MEMO,
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

ALL_TASKS: Dict[str, Task] = {
    "easy": TASK_EASY,
    "medium": TASK_MEDIUM,
    "hard": TASK_HARD,
}


def get_task(task_id: str) -> Task:
    if task_id not in ALL_TASKS:
        raise ValueError(f"Unknown task_id '{task_id}'. Choose from: {list(ALL_TASKS)}")
    return ALL_TASKS[task_id]
