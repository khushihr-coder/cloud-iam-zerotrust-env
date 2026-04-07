# Dockerfile — Cloud-IAM-ZeroTrust-Env
# Optimised for Hugging Face Spaces (port 7860, non-root user)

FROM python:3.10-slim

# Keep Python output unbuffered for [STEP] log streaming
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=7860

WORKDIR /app

# Install dependencies first (layer caching)
RUN pip install --no-cache-dir \
    "openenv-core>=0.1.0" \
    "pydantic>=2.0.0" \
    "openai>=1.0.0" \
    "fastapi>=0.100.0" \
    "uvicorn[standard]>=0.23.0"

# Copy project files
COPY models.py tasks.py graders.py env.py server.py openenv.yaml ./

# HF Spaces runs as non-root — create user
RUN useradd -m -u 1000 appuser && chown -R appuser /app
USER appuser

# Expose HF Spaces port
EXPOSE 7860

# Start the FastAPI server directly — no dependency on openenv CLI
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "7860", \
     "--workers", "1", "--log-level", "info"]
