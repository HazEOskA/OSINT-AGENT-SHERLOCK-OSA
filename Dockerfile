FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system sherlock && useradd --system --gid sherlock --create-home sherlock

WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-cache-dir .

USER sherlock
EXPOSE 8787
CMD ["sherlock-osa", "serve"]
