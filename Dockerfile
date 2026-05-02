FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip setuptools wheel

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

EXPOSE 8000
CMD ["uvicorn", "src.nexus.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
