.DEFAULT_GOAL := help

COMPOSE := docker compose -f docker-compose.dev.yml
SERVICE := fastback-api

.PHONY: help install up up-d down down-v down-all logs sh format lint fix test test-cov test-cov-html migrate migrate-new migrate-down migrate-history

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install dependencies and pre-commit hooks
	poetry install && poetry run pre-commit install --hook-type commit-msg

up: ## Start Docker dev server (migrations run automatically)
	$(COMPOSE) up -d --build
	$(COMPOSE) logs -f

up-d: ## Start Docker dev server in detached mode
	$(COMPOSE) up -d --build

down: ## Stop containers
	$(COMPOSE) down $(ARGS)

down-v: ## Stop containers and remove volumes
	$(COMPOSE) down -v

down-all: ## Stop containers, remove volumes, images, and orphans
	$(COMPOSE) down --rmi all -v --remove-orphans

logs: ## Tail logs
	$(COMPOSE) logs -f $(SERVICE)

sh: ## Shell into container
	$(COMPOSE) exec $(SERVICE) sh

format: ## Format code (ruff)
	$(COMPOSE) exec $(SERVICE) ruff format .

lint: ## Lint code (ruff) (ARGS=--unsafe etc.)
	$(COMPOSE) exec $(SERVICE) ruff check . $(ARGS)

fix: ## Auto-fix lint issues (ARGS=--unsafe etc.)
	$(COMPOSE) exec $(SERVICE) ruff check . --fix $(ARGS)
	$(COMPOSE) exec $(SERVICE) ruff format .

test: ## Run tests
	$(COMPOSE) exec $(SERVICE) pytest -v

test-cov: ## Run tests with coverage report
	$(COMPOSE) exec $(SERVICE) pytest --cov=app --cov-report=term-missing

test-cov-html: ## Run tests with HTML coverage report
	$(COMPOSE) exec $(SERVICE) pytest --cov=app --cov-report=html:htmlcov --cov-report=json:coverage.json --cov-report=term
	@echo "\nCoverage report: htmlcov/index.html"

# Alembic migrations
migrate: ## Run migrations (upgrade to head)
	$(COMPOSE) exec $(SERVICE) alembic upgrade head

migrate-new: ## Create new migration (usage: make migrate-new MSG="description")
	$(COMPOSE) exec $(SERVICE) alembic revision --autogenerate -m "$(MSG)"

migrate-down: ## Rollback last migration
	$(COMPOSE) exec $(SERVICE) alembic downgrade -1

migrate-history: ## Show migration history
	$(COMPOSE) exec $(SERVICE) alembic history --verbose
