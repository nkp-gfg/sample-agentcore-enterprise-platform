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

# Install Node.js for claude-code CLI via checksum-verified official tarball
ARG NODE_VERSION=22.23.5
ARG NODE_SHA256_ARM64=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09
ARG NODE_SHA256_X64=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl ca-certificates xz-utils && \
    arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      arm64) node_arch="arm64"; node_sha="${NODE_SHA256_ARM64}" ;; \
      amd64) node_arch="x64"; node_sha="${NODE_SHA256_X64}" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" -o /tmp/node.tar.xz && \
    echo "${node_sha}  /tmp/node.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 && \
    rm -f /tmp/node.tar.xz && \
    rm -rf /var/lib/apt/lists/*

# Install claude-code globally
RUN npm install -g @anthropic-ai/claude-code@2.1.73

# Copy and install agent-specific requirements
COPY claude-sdk-multi-agent/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir aws-opentelemetry-distro==0.16.0

# Copy shared utilities
COPY shared/ shared/

# Create non-root user and ensure claude config dir is writable
RUN useradd -m -u 1000 bedrock_agentcore && \
    mkdir -p /home/bedrock_agentcore/.claude && \
    chown -R bedrock_agentcore:bedrock_agentcore /home/bedrock_agentcore/.claude
USER bedrock_agentcore

ENV CLAUDE_CONFIG_DIR=/home/bedrock_agentcore/.claude

EXPOSE 8080

# Copy agent code files
COPY claude-sdk-multi-agent/agent.py .
COPY claude-sdk-multi-agent/code_int_mcp/ code_int_mcp/
COPY claude-sdk-multi-agent/agents/ agents/

# Healthcheck using Python
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1

# Start agent with OpenTelemetry instrumentation
CMD ["opentelemetry-instrument", "python", "-m", "agent"]
