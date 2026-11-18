# Adapted from fullstack-solution-template-for-agentcore
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /app

# Container environment configuration
ENV DOCKER_CONTAINER=1 \
    OTEL_PYTHON_LOG_CORRELATION=true \
    PYTHONUNBUFFERED=1

# requirements.txt is the hash-locked closure of requirements.in. An unprivileged
# build user installs it into /opt/venv, which the runtime user can only read.
RUN useradd -m -u 1000 bedrock_agentcore && \
    useradd -r -M -u 999 -s /usr/sbin/nologin deps_installer && \
    install -d -o deps_installer -g deps_installer /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY agui-strands-agent/requirements.txt requirements.txt
USER deps_installer
RUN python -m venv /opt/venv && \
    pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements.txt

# Copy shared utilities
COPY shared/ shared/

USER bedrock_agentcore

EXPOSE 8080

# Copy agent code and tools
COPY agui-strands-agent/agent.py .
COPY agui-strands-agent/tools/ tools/

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1

# Start agent with OpenTelemetry instrumentation
CMD ["opentelemetry-instrument", "python", "-m", "agent"]
