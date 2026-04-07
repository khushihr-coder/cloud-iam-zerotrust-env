"""
models.py — Typed Pydantic models for Cloud-IAM-ZeroTrust-Env.

Three actions:
  AnalyzePolicy   — diff current policy against audit log (planning step)
  TestPolicy      — simulate API calls against a draft policy (max 3/episode)
  SubmitFinalPolicy — end episode, trigger terminal grader
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ActionType(str, Enum):
    ANALYZE = "AnalyzePolicy"
    TEST = "TestPolicy"
    SUBMIT = "SubmitFinalPolicy"


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

class AnalyzePolicyAction(BaseModel):
    """
    Ask the environment to diff the provided policy against the audit log.
    Returns which required actions are missing and which wildcards remain.
    Grants +0.1 reward on first use to encourage planning before testing.
    """
    action_type: Literal[ActionType.ANALYZE] = ActionType.ANALYZE
    policy_json: str = Field(
        ...,
        description="JSON string of the IAM policy to analyse.",
    )


class TestPolicyAction(BaseModel):
    """
    Run the simulated API call suite against the provided policy.
    Capped at 3 uses per episode. Escalating penalties: -0.05 / -0.10 / -0.20.
    Exceeding the cap forces done=True with a -1.0 terminal penalty.
    """
    action_type: Literal[ActionType.TEST] = ActionType.TEST
    policy_json: str = Field(
        ...,
        description="JSON string of the draft IAM policy to test.",
    )


class SubmitFinalPolicyAction(BaseModel):
    """
    Submit the final policy. Ends the episode (done=True) and triggers
    the deterministic terminal grader for the heavy reward signal.
    """
    action_type: Literal[ActionType.SUBMIT] = ActionType.SUBMIT
    policy_json: str = Field(
        ...,
        description="JSON string of the final IAM policy to submit.",
    )


# Union type used by env.step()
IAMAction = Union[AnalyzePolicyAction, TestPolicyAction, SubmitFinalPolicyAction]


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

class IAMObservation(BaseModel):
    """Everything the agent sees at each step."""

    # Static context (set at reset, never changes within an episode)
    task_id: str = Field(..., description="Task identifier: 'easy' | 'medium' | 'hard'")
    task_description: str = Field(..., description="Human-readable task brief.")
    initial_policy: str = Field(..., description="The original over-permissive policy JSON.")
    audit_log: List[str] = Field(
        ...,
        description=(
            "Ordered list of API calls the application actually made, e.g. "
            "'s3:GetObject on arn:aws:s3:::report-bucket/data.csv'."
        ),
    )

    # Mutable state (updated after each action)
    current_policy: str = Field(..., description="The policy JSON as last submitted by the agent.")
    simulator_feedback: str = Field(
        ...,
        description=(
            "Plain-text feedback from the last action: diff results, "
            "test pass/fail summary, or grader verdict."
        ),
    )
    test_calls_used: int = Field(
        default=0,
        ge=0,
        le=3,
        description="Number of TestPolicy calls consumed this episode (max 3).",
    )
    analyze_used: bool = Field(
        default=False,
        description="Whether AnalyzePolicy has been called at least once.",
    )
    step_count: int = Field(default=0, ge=0, description="Total steps taken so far.")

    # Terminal info
    done: bool = Field(default=False, description="True when the episode has ended.")
    last_action_error: Optional[str] = Field(
        default=None,
        description="Non-None if the last action caused a recoverable error.",
    )


# ---------------------------------------------------------------------------
# Reward
# ---------------------------------------------------------------------------

class IAMReward(BaseModel):
    """
    Structured reward breakdown so inference scripts can log components.
    The scalar `total` is what the RL loop uses.
    """
    total: float = Field(..., description="Scalar reward for this step.")

    # Components (informational)
    analyze_bonus: float = Field(default=0.0, description="+0.1 on first AnalyzePolicy use.")
    test_penalty: float = Field(default=0.0, description="Escalating penalty for TestPolicy calls.")
    wildcard_delta: float = Field(
        default=0.0,
        description="Per-wildcard-removed bonus from TestPolicy diff.",
    )
    broken_service_penalty: float = Field(
        default=0.0,
        description="Penalty for required services broken during TestPolicy.",
    )
    terminal_score: float = Field(
        default=0.0,
        description="Final grader score at SubmitFinalPolicy (0.0–1.0 scaled).",
    )
    cap_exceeded_penalty: float = Field(
        default=0.0,
        description="-1.0 if TestPolicy cap was exceeded.",
    )

    class Config:
        frozen = True


# ---------------------------------------------------------------------------
# Step result (what env.step() returns)
# ---------------------------------------------------------------------------

class StepResult(BaseModel):
    observation: IAMObservation
    reward: float
    reward_breakdown: IAMReward
    done: bool
    info: Dict[str, Any] = Field(default_factory=dict)
