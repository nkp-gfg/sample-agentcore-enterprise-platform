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

# Install Node.js for claude-code CLI from the official release tarball.
# The SHA-256 values are from the signed SHASUMS256.txt for this release;
# update them together with NODE_VERSION.
ENV NODE_VERSION=26.13.1
RUN set -eu && \
    apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl libatomic1 xz-utils && \
    rm -rf /var/lib/apt/lists/* && \
    case "$(dpkg --print-architecture)" in \
      arm64) NODE_ARCH=arm64 NODE_SHA256=89e1853138db51e8b82d3e98ba9c0d3f2956a28e5e55ea1b7e12d25aae92d5dd ;; \
      amd64) NODE_ARCH=x64 NODE_SHA256=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864 ;; \
      *) echo "unsupported architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac && \
    NODE_TARBALL="node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" && \
    curl -fsSL -o "/tmp/${NODE_TARBALL}" "https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TARBALL}" && \
    printf "%s  %s\n" "${NODE_SHA256}" "/tmp/${NODE_TARBALL}" > /tmp/node.sha256 && \
    sha256sum -c /tmp/node.sha256 && \
    tar -xJf "/tmp/${NODE_TARBALL}" -C /usr/local --strip-components=1 --no-same-owner && \
    rm -f "/tmp/${NODE_TARBALL}" /tmp/node.sha256 && \
    node --version && npm --version

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
