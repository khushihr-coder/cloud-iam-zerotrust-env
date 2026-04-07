"""
env.py — Core environment for Cloud-IAM-ZeroTrust-Env.

Inherits from openenv.core.Environment as required by openenv validate.
  - reset()  → returns IAMObservation  (NOT StepResult — spec requirement)
  - step()   → returns IAMObservation  (reward embedded in observation.reward)
  - state()  → returns IAMState

Key design decisions:
  - reward is stored on observation.reward (OpenEnv Observation base field)
  - IAMState holds internal episode counters (not exposed to agent)
"""

from __future__ import annotations

from typing import Any, Optional

from openenv.core import Action, Environment, Observation, State

from graders import analyze_policy, count_wildcards, grade
from models import ActionType
from tasks import Task, get_task


# ---------------------------------------------------------------------------
# OpenEnv-compliant Observation
# ---------------------------------------------------------------------------

class IAMObservation(Observation):
    """
    Everything the agent sees each step.
    Inherits done, reward, metadata from openenv.core.Observation.
    """
    # Static context
    task_id: str = ""
    task_description: str = ""
    initial_policy: str = ""
    audit_log: list[str] = []

    # Mutable state
    current_policy: str = ""
    simulator_feedback: str = ""
    test_calls_used: int = 0
    analyze_used: bool = False
    last_action_error: Optional[str] = None
    reward_breakdown: dict[str, float] = {}


# ---------------------------------------------------------------------------
# OpenEnv-compliant Action
# ---------------------------------------------------------------------------

class IAMActionWrapper(Action):
    """
    Single Action class for create_fastapi_app.
    Agent sends action_type + policy_json.
    """
    action_type: str  # "AnalyzePolicy" | "TestPolicy" | "SubmitFinalPolicy"
    policy_json: str = ""


# ---------------------------------------------------------------------------
# OpenEnv-compliant State
# ---------------------------------------------------------------------------

class IAMState(State):
    """Internal episode counters returned by state() endpoint."""
    task_id: str = ""
    test_calls_used: int = 0
    analyze_used: bool = False
    wildcards_at_start: int = 0


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

class CloudIAMEnv(Environment[IAMActionWrapper, IAMObservation, IAMState]):
    """
    Cloud IAM Least-Privilege Optimizer environment.

    Episode flow:
      reset(task_id)               -> IAMObservation (reward=0.0)
      step(AnalyzePolicy)          -> +0.1 first use, analysis diff
      step(TestPolicy)             -> escalating penalty, simulation results
      step(SubmitFinalPolicy)      -> terminal grader score, done=True
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._obs: IAMObservation = IAMObservation()
        self._task: Optional[Task] = None

    # ------------------------------------------------------------------
    # reset() — returns Observation (OpenEnv spec)
    # ------------------------------------------------------------------

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task_id: str = "easy",
        **kwargs: Any,
    ) -> IAMObservation:
        """Initialise a fresh episode. Returns the initial IAMObservation."""
        self._task = get_task(task_id)

        self._obs = IAMObservation(
            done=False,
            reward=0.0,
            metadata={"episode_id": episode_id or "", "seed": seed, "step_count": 0},
            task_id=self._task.id,
            task_description=(
                self._task.description
                + (f"\n\nSECURITY MEMO:\n{self._task.security_memo}"
                   if self._task.security_memo else "")
            ),
            initial_policy=self._task.initial_policy,
            audit_log=list(self._task.audit_log),
            current_policy=self._task.initial_policy,
            simulator_feedback=(
                "Episode started. Use AnalyzePolicy to understand the gap, "
                "TestPolicy (max 3x) to validate, then SubmitFinalPolicy."
            ),
            test_calls_used=0,
            analyze_used=False,
            last_action_error=None,
            reward_breakdown={},
        )
        return self._obs

    # ------------------------------------------------------------------
    # step() — returns Observation (OpenEnv spec)
    # ------------------------------------------------------------------

    def step(
        self,
        action: IAMActionWrapper,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> IAMObservation:
        """Process one action and return updated observation with embedded reward."""

        if self._obs.done:
            raise ValueError("Episode is done. Call reset() to start a new episode.")

        self._obs.metadata["step_count"] = self._obs.metadata.get("step_count", 0) + 1
        self._obs.last_action_error = None

        reward_total: float = 0.0
        breakdown: dict[str, float] = {
            "analyze_bonus": 0.0,
            "test_penalty": 0.0,
            "wildcard_delta_bonus": 0.0,
            "terminal_score": 0.0,
            "cap_exceeded_penalty": 0.0,
        }

        try:
            atype = action.action_type
            policy = action.policy_json

            # ── AnalyzePolicy ──────────────────────────────────────────
            if atype == ActionType.ANALYZE:
                analysis = analyze_policy(policy, self._obs.audit_log)
                self._obs.current_policy = policy
                self._obs.simulator_feedback = analysis.feedback

                if not self._obs.analyze_used:
                    breakdown["analyze_bonus"] = 0.10
                    reward_total += 0.10
                    self._obs.analyze_used = True

            # ── TestPolicy ─────────────────────────────────────────────
            elif atype == ActionType.TEST:
                self._obs.test_calls_used += 1

                if self._obs.test_calls_used > 3:
                    self._obs.simulator_feedback = (
                        "CRITICAL: TestPolicy cap (3) exceeded. Episode terminated."
                    )
                    self._obs.done = True
                    breakdown["cap_exceeded_penalty"] = -1.0
                    reward_total -= 1.0
                else:
                    penalties = {1: -0.05, 2: -0.10, 3: -0.20}
                    pen = penalties[self._obs.test_calls_used]
                    breakdown["test_penalty"] = pen
                    reward_total += pen

                    self._obs.current_policy = policy
                    analysis = analyze_policy(policy, self._obs.audit_log)
                    self._obs.simulator_feedback = (
                        f"Test {self._obs.test_calls_used}/3 complete.\n"
                        + analysis.feedback
                    )

                    # Dense signal: reward wildcard reduction with full coverage
                    wildcards_now = count_wildcards(policy)
                    wildcards_start = count_wildcards(self._obs.initial_policy)
                    if analysis.coverage_ratio == 1.0 and wildcards_now < wildcards_start:
                        delta_bonus = round(
                            0.05 * (wildcards_start - wildcards_now) / max(wildcards_start, 1),
                            4,
                        )
                        breakdown["wildcard_delta_bonus"] = delta_bonus
                        reward_total += delta_bonus

            # ── SubmitFinalPolicy ──────────────────────────────────────
            elif atype == ActionType.SUBMIT:
                self._obs.current_policy = policy
                self._obs.done = True

                result = grade(self._obs.task_id, policy)
                self._obs.simulator_feedback = (
                    result.feedback + "\n\nDetails:\n" + "\n".join(result.details)
                )
                breakdown["terminal_score"] = result.score
                reward_total += result.score

            else:
                raise ValueError(
                    f"Unknown action_type '{atype}'. "
                    "Use AnalyzePolicy, TestPolicy, or SubmitFinalPolicy."
                )

        except ValueError as exc:
            self._obs.last_action_error = str(exc)
            self._obs.simulator_feedback = f"ACTION ERROR: {exc}"
            reward_total -= 0.05

        except Exception as exc:
            self._obs.last_action_error = f"Runtime error: {exc}"
            self._obs.simulator_feedback = self._obs.last_action_error
            reward_total -= 0.05

        self._obs.reward = round(reward_total, 4)
        self._obs.reward_breakdown = breakdown
        return self._obs

    # ------------------------------------------------------------------
    # state()
    # ------------------------------------------------------------------

    def state(self) -> IAMState:
        """Return internal episode state."""
        return IAMState(
            step_count=self._obs.metadata.get("step_count", 0),
            task_id=self._obs.task_id,
            test_calls_used=self._obs.test_calls_used,
            analyze_used=self._obs.analyze_used,
            wildcards_at_start=count_wildcards(self._obs.initial_policy),
        )
