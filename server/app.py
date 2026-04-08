"""
server/app.py — FastAPI server for Cloud-IAM-ZeroTrust-Env.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Add parent directory to path so we can import env, models, etc.
sys.path.insert(0, str(Path(__file__).parent.parent))

from openenv.core import create_fastapi_app

from env import CloudIAMEnv, IAMActionWrapper, IAMObservation

app = create_fastapi_app(
    env=CloudIAMEnv,
    action_cls=IAMActionWrapper,
    observation_cls=IAMObservation,
    max_concurrent_envs=50,
)


@app.get("/")
def home():
    return {
        "message": "Cloud IAM Zero Trust Env is running 🚀",
        "endpoints": [
            "/reset (POST)",
            "/step (POST)",
            "/state (GET)",
            "/schema (GET)",
            "/health (GET)"
        ]
    }


@app.get("/docs")
def docs_redirect():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")


def main():
    """Main entry point for running the server."""
    import uvicorn
    port = int(os.getenv("PORT", "7860"))
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=port,
        workers=1,
        log_level="info",
    )


if __name__ == "__main__":
    main()
