.PHONY: init run db-up db-down migrate

init:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt
	.venv/bin/pre-commit install

db-up:
	docker compose up -d

db-down:
	docker compose down

migrate:
	.venv/bin/alembic upgrade head

run:
	.venv/bin/python -m src.core.main
