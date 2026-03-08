.PHONY: init run db-up db-down migrate build up down restart logs

# ── Local development ────────────────────────────────────────────────────────

init:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt
	.venv/bin/pre-commit install

run:
	.venv/bin/python -m src.core.main

migrate:
	.venv/bin/alembic upgrade head

# ── Docker ───────────────────────────────────────────────────────────────────

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose restart iris

logs:
	docker compose logs -f iris

db-up:
	docker compose up -d postgres

db-down:
	docker compose down postgres
