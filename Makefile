.PHONY: ci dev lint test test-all type docker-up docker-down langfuse-flush

ci:
	ruff check . && ruff format --check . && mypy src/ --strict && pytest tests/ -m "not integration" --cov=src/nexus --cov-fail-under=80

dev:
	uvicorn src.nexus.api.main:app --reload --host 0.0.0.0 --port 8000

lint:
	ruff check . --fix && ruff format .

test:
	pytest tests/ -m "not integration" -v

test-all:
	pytest tests/ -v

type:
	mypy src/ --strict

docker-up:
	docker compose up -d

docker-down:
	docker compose down

langfuse-flush:
	python -c "from nexus.observability.langfuse import flush_langfuse; flush_langfuse()"
