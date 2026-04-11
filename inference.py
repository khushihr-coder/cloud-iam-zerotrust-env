"""
inference.py — Baseline inference script for Cloud-IAM-ZeroTrust-Env.

Strictly conforms to the [START] / [STEP] / [END] stdout logging format.
Runs ALL tasks (easy, medium, hard) sequentially so the validator sees
3 graded episodes in one execution.
"""

import json
import os
import textwrap
from typing import List, Optional

from openai import OpenAI

from env import CloudIAMEnv, IAMActionWrapper
from models import ActionType

API_BASE_URL: str = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
MODEL_NAME: str = os.getenv("MODEL_NAME", "gpt-4o-mini")
API_KEY: Optional[str] = os.getenv("API_KEY") or os.getenv("HF_TOKEN")

BENCHMARK: str = "cloud-iam-zerotrust"
MAX_STEPS: int = 10
SUCCESS_SCORE_THRESHOLD: float = 0.8
TEMPERATURE: float = 0.2

# If TASK_ID is set run only that task, otherwise run all 3
_task_env = os.getenv("TASK_ID", "").strip()
TASKS_TO_RUN: List[str] = [_task_env] if _task_env else ["easy", "medium", "hard"]

SYSTEM_PROMPT = textwrap.dedent("""
    You are an expert AWS Cloud Security Engineer specialising in IAM least-privilege.

    You receive an overly permissive IAM JSON policy and an audit log of the
    application'"'"'s actual API calls. Your job: rewrite the policy to allow ONLY
    the exact actions and resources in the audit log — no wildcards.

    You have exactly 3 tools. Respond with a single JSON object only:

    1. Analyse the gap (free, +0.1 reward first use):
       {"action": "AnalyzePolicy", "policy_json": "<your draft policy>"}

    2. Test your draft (MAX 3 USES — escalating -0.05/-0.10/-0.20 penalties):
       {"action": "TestPolicy", "policy_json": "<your draft policy>"}

    3. Submit your final answer (ends episode, scored 0.0-1.0):
       {"action": "SubmitFinalPolicy", "policy_json": "<your final policy>"}

    STRATEGY:
    - Step 1: Always call AnalyzePolicy first to see which wildcards remain.
    - Step 2: Write a tight policy and TestPolicy once to verify.
    - Step 3: SubmitFinalPolicy. Never exhaust all 3 tests — save at least 1.

    OUTPUT: Return ONLY a valid JSON object with keys "action" and "policy_json".
    No markdown, no explanation, no extra keys.
""").strip()


def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    safe_action = action.replace("\n", " ").replace("\r", "")
    if len(safe_action) > 120:
        safe_action = safe_action[:117] + "..."
    print(
        f"[STEP] step={step} action={safe_action} "
        f"reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.4f} rewards={rewards_str}",
        flush=True,
    )


def get_model_action(
    client: OpenAI,
    step: int,
    obs_task_description: str,
    obs_audit_log: List[str],
    obs_simulator_feedback: str,
    obs_test_calls_used: int,
    history: List[str],
) -> dict:
    history_block = "\n".join(history[-3:]) if history else "None"
    user_prompt = textwrap.dedent(f"""
        Step: {step}
        Task: {obs_task_description}

        Audit Log (these are ALL the API calls the app actually makes):
        {chr(10).join(f"  - {entry}" for entry in obs_audit_log)}

        Feedback from last action:
        {obs_simulator_feedback}

        Tests used: {obs_test_calls_used}/3
        Recent history:
        {history_block}

        Respond with exactly one JSON object: {{"action": "...", "policy_json": "..."}}
    """).strip()

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=TEMPERATURE,
            max_tokens=800,
            response_format={"type": "json_object"},
        )
        text = (completion.choices[0].message.content or "").strip()
        return json.loads(text)
    except Exception as exc:
        print(f"[DEBUG] LLM call failed: {exc}", flush=True)
        return {"action": "SubmitFinalPolicy", "policy_json": "{}"}


def run_episode(client: OpenAI, task_name: str) -> None:
    """Run a single episode for task_name and emit [START]/[STEP]/[END] logs."""
    env = CloudIAMEnv()
    rewards: List[float] = []
    history: List[str] = []
    steps_taken: int = 0
    score: float = 0.0
    success: bool = False

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        obs = env.reset(task_id=task_name)

        for step in range(1, MAX_STEPS + 1):
            if obs.done:
                break

            parsed = get_model_action(
                client=client,
                step=step,
                obs_task_description=obs.task_description,
                obs_audit_log=obs.audit_log,
                obs_simulator_feedback=obs.simulator_feedback,
                obs_test_calls_used=obs.test_calls_used,
                history=history,
            )

            action_type: str = parsed.get("action", "SubmitFinalPolicy")
            policy_json: str = parsed.get("policy_json", "{}")
            action_summary = f"{action_type}(policy_len={len(policy_json)})"

            reward: float = 0.0
            done: bool = False
            error: Optional[str] = None

            try:
                action_map = {
                    "AnalyzePolicy": ActionType.ANALYZE,
                    "TestPolicy": ActionType.TEST,
                    "SubmitFinalPolicy": ActionType.SUBMIT,
                }
                resolved_type = action_map.get(action_type, ActionType.SUBMIT)
                action_obj = IAMActionWrapper(
                    action_type=resolved_type,
                    policy_json=policy_json,
                )
                obs = env.step(action_obj)
                reward = obs.reward or 0.0
                done = obs.done
                error = obs.last_action_error

                if done:
                    score = obs.reward_breakdown.get("terminal_score", 0.0)

            except Exception as exc:
                reward = -0.05
                error = str(exc)
                print(f"[DEBUG] env.step() error: {exc}", flush=True)

            rewards.append(reward)
            steps_taken = step

            log_step(step=step, action=action_summary, reward=reward, done=done, error=error)
            history.append(
                f"Step {step}: {action_type} -> reward={reward:+.2f} | "
                f"{obs.simulator_feedback[:80]}"
            )

            if done:
                break

        # If episode never terminated, force a SubmitFinalPolicy so score is never 0.0
        if not obs.done:
            try:
                last_policy = obs.current_policy or "{}"
                action_obj = IAMActionWrapper(
                    action_type=ActionType.SUBMIT,
                    policy_json=last_policy,
                )
                obs = env.step(action_obj)
                reward = obs.reward or 0.0
                score = obs.reward_breakdown.get("terminal_score", 0.0)
                rewards.append(reward)
                steps_taken += 1
                log_step(
                    step=steps_taken,
                    action=f"SubmitFinalPolicy(forced,policy_len={len(last_policy)})",
                    reward=reward,
                    done=True,
                    error=None,
                )
            except Exception as exc:
                print(f"[DEBUG] Forced submit error: {exc}", flush=True)

        # Clamp score to be strictly between 0 and 1
        if score <= 0.0:
            score = 0.0001
        elif score >= 1.0:
            score = 0.9999

        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as exc:
        print(f"[DEBUG] Fatal error in episode: {exc}", flush=True)
        score = 0.0001
        success = False

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


def main() -> None:
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    for task_name in TASKS_TO_RUN:
        run_episode(client, task_name)


if __name__ == "__main__":
    main()