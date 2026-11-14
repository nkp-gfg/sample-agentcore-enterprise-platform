# Adapted from agui-langgraph-agent/Dockerfile for the layer-2 god-agent pattern.
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Python 3.13: the pinned deepagents/langgraph/copilotkit all accept it, and
# layer-2 explicitly asks for 3.13 (the workshop pattern is still on 3.12).
FROM public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /app

# Container environment configuration
ENV DOCKER_CONTAINER=1 \
    OTEL_PYTHON_LOG_CORRELATION=true \
    PYTHONUNBUFFERED=1

# Install agent-specific requirements first (Docker layer cache: pip step is
# invalidated only when requirements.txt changes, not on every source edit).
COPY god-agent/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir aws-opentelemetry-distro==0.16.0

# Copy shared utilities
COPY shared/ shared/

# Non-root runtime user (same uid as the workshop patterns).
RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore

EXPOSE 8080

# Agent code. Dockerfile ``CMD`` runs `python -m agent`, so the layout at
# /app is a flat set of modules beside agent.py; all intra-agent imports
# are absolute (`from gateway_client import ...`). This matches the workshop
# pattern `agent-code/agui-langgraph-agent/`.
COPY god-agent/agent.py .
COPY god-agent/review.py .
COPY god-agent/guardrail.py .
COPY god-agent/subagents.py .
COPY god-agent/filesystem.py .
COPY god-agent/leaves.py .
COPY god-agent/rate_limit.py .
COPY god-agent/ssm_config.py .
COPY god-agent/gateway_client.py .
COPY god-agent/checkpointer.py .
COPY god-agent/global-bundle.pem .

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1

# Start agent with OpenTelemetry instrumentation (same shape as the other
# AG-UI pattern — AgentCore proxies AG-UI SSE events unchanged).
CMD ["opentelemetry-instrument", "python", "-m", "agent"]
