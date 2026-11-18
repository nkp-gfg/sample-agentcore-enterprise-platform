# The simulated customer container — a plain agent service with its own HTTP
# contract (POST /run, GET /healthz on :8000). The migration adapter is built
# FROM this image; nothing here knows about AgentCore.
FROM public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
# requirements.txt is the hash-locked closure of requirements.in. An unprivileged
# build user installs it into /opt/venv, which the runtime user can only read.
RUN groupadd --gid 10001 migrated-agent \
    && useradd --uid 10001 --gid 10001 --no-create-home migrated-agent \
    && useradd -r -M -u 999 -s /usr/sbin/nologin deps_installer \
    && install -d -o deps_installer -g deps_installer /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt .
USER deps_installer
RUN python -m venv /opt/venv \
    && pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements.txt
COPY --chown=10001:10001 agent.py server.py ./
EXPOSE 8000
USER 10001:10001
CMD ["python", "server.py"]
