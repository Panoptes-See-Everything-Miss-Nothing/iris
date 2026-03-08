FROM python:3.13-slim

# Non-root user for least-privilege execution
RUN groupadd --gid 1001 iris \
    && useradd --uid 1001 --gid iris --no-create-home iris

WORKDIR /app

# Install only runtime dependencies — dev tools stay out of the image
COPY requirements.txt .
RUN pip install --no-cache-dir \
    aiohttp==3.13.3 \
    alembic==1.17.2 \
    psycopg2-binary==2.9.11 \
    requests==2.32.5 \
    SQLAlchemy==2.0.45

COPY src/ ./src/

# Pre-create writable directories and hand them to the non-root user
RUN mkdir -p src/fixtures logs \
    && chown -R iris:iris /app

USER iris

CMD ["python", "-m", "src.core.main"]
