"""
server.py — Entry point for Cloud-IAM-ZeroTrust-Env.
Imports the FastAPI app from server/app.py
"""

import os
import uvicorn

from server.app import app

# run server
if __name__ == "__main__":
    port = int(os.getenv("PORT", "7860"))
    uvicorn.run(
        "server.app:app",
        host="0.0.0.0",
        port=port,
        workers=1,
        log_level="info",
    )
