FROM public.ecr.aws/docker/library/python:3.11-slim
WORKDIR /app
# requirements.txt is the hash-locked closure of requirements.in. An unprivileged
# build user installs it into /opt/venv, which the runtime user can only read.
RUN useradd -m -u 1000 bedrock_agentcore && \
    useradd -r -M -u 999 -s /usr/sbin/nologin deps_installer && \
    install -d -o deps_installer -g deps_installer /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY orchestrator/requirements.txt .
USER deps_installer
RUN python -m venv /opt/venv && \
    pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements.txt
USER bedrock_agentcore
EXPOSE 8080
COPY orchestrator/agent.py .
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1
CMD ["opentelemetry-instrument", "python", "-m", "agent"]
