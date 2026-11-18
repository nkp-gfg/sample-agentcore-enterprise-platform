FROM public.ecr.aws/docker/library/python:3.11-slim
WORKDIR /app
COPY orchestrator/requirements.lock.txt requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary :all: -r requirements.txt
RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore
EXPOSE 8080
COPY orchestrator/agent.py .
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping', timeout=2)" || exit 1
CMD ["opentelemetry-instrument", "python", "-m", "agent"]
