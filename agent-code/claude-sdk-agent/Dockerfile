# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /app

# Container environment configuration.
# CLAUDE_CODE_USE_BEDROCK=1 is required for the Claude CLI to use Bedrock.
ENV DOCKER_CONTAINER=1 \
    OTEL_PYTHON_LOG_CORRELATION=true \
    PYTHONUNBUFFERED=1 \
    CLAUDE_CODE_USE_BEDROCK=1

# Install Node.js for claude-code CLI
RUN apt-get update && \
    apt-get install -y curl && \
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# Install claude-code globally
RUN npm install -g @anthropic-ai/claude-code@2.1.73

# Create non-root user and ensure claude config dir is writable.
# requirements.txt is the hash-locked closure of requirements.in. An unprivileged
# build user installs it into /opt/venv, which the runtime user can only read.
RUN useradd -m -u 1000 bedrock_agentcore && \
    mkdir -p /home/bedrock_agentcore/.claude && \
    chown -R bedrock_agentcore:bedrock_agentcore /home/bedrock_agentcore/.claude && \
    useradd -r -M -u 999 -s /usr/sbin/nologin deps_installer && \
    install -d -o deps_installer -g deps_installer /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY claude-sdk-agent/requirements.txt requirements.txt
USER deps_installer
RUN python -m venv /opt/venv && \
    pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements.txt

USER bedrock_agentcore

ENV CLAUDE_CONFIG_DIR=/home/bedrock_agentcore/.claude

EXPOSE 8080

# Copy shared utilities and agent code
COPY shared/ shared/
COPY claude-sdk-agent/agent.py .
COPY claude-sdk-agent/code_int_mcp/ code_int_mcp/

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1

# Start agent with OpenTelemetry instrumentation
CMD ["opentelemetry-instrument", "python", "-m", "agent"]
