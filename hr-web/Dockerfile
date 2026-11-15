FROM public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY bff/requirements.txt bff/requirements.txt
RUN pip install --no-cache-dir -r bff/requirements.txt

COPY bff/ bff/
COPY public/ public/

RUN useradd -m -u 1000 hrweb && chown -R hrweb:hrweb /app
USER hrweb

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)" || exit 1

CMD ["uvicorn", "bff.app:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips=*", "--timeout-graceful-shutdown", "60"]
