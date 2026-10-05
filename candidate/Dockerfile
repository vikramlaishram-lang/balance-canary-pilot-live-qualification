FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/
COPY balance /app/balance
RUN python -m pip install --no-cache-dir '.[deploy]' && \
    groupadd --gid 10001 balance && useradd --uid 10001 --gid 10001 --no-create-home balance && \
    mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
EXPOSE 8080
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "90", "--access-logfile", "-", "balance.http:create_app()"]
