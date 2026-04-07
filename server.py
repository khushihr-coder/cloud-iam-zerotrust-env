"""
server.py — FastAPI server for Cloud-IAM-ZeroTrust-Env.

Uses openenv.core.create_fastapi_app to generate spec-compliant
/reset, /step, /state, /schema endpoints automatically.

The validator pings POST /reset → must return 200 + IAMObservation JSON.
"""

from __future__ import annotations

import os

import uvicorn
from openenv.core import create_fastapi_app

from env import CloudIAMEnv, IAMActionWrapper, IAMObservation

# create_fastapi_app wires:
#   POST /reset  → env.reset()   returns IAMObservation
#   POST /step   → env.step()    returns IAMObservation
#   GET  /state  → env.state()   returns IAMState
#   GET  /schema → action + observation JSON schemas
#   GET  /health → health check
app = create_fastapi_app(
    env=CloudIAMEnv,               # factory callable
    action_cls=IAMActionWrapper,
    observation_cls=IAMObservation,
    max_concurrent_envs=50,
)

if __name__ == "__main__":
    port = int(os.getenv("PORT", "7860"))
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=port,
        workers=1,
        log_level="info",
    )
