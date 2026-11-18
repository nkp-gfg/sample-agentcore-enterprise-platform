FROM public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

# halo has no py3 wheel: it is built from its hashed sdist with the hashed
# setuptools from build-requirements.lock.txt (see scripts/lock_requirements.py).
COPY strands-agent/build-requirements.lock.txt build-requirements.txt
COPY strands-agent/requirements.lock.txt requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r build-requirements.txt && \
    pip install --no-cache-dir --require-hashes --only-binary :all: --no-binary halo \
        --no-build-isolation -r requirements.txt

COPY shared/ shared/

RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore

EXPOSE 8080

COPY strands-agent/agent.py .
COPY strands-agent/tools/ tools/

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1

CMD ["opentelemetry-instrument", "python", "agent.py"]
