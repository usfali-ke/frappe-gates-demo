# Convenience wrappers for the local loop. CI never calls these: the pipeline
# jobs are the source of truth for what a gate runs.

BENCH ?= $(HOME)/frappe-bench
SITE ?= fgd.local

.PHONY: help lint test test-junit coverage compose-up compose-down image clean

help:
	@echo "make lint          ruff (the pipeline's code-quality control)"
	@echo "make test          bench run-tests against $(SITE) in $(BENCH)"
	@echo "make test-junit    same, writing reports/unit-tests/junit.xml"
	@echo "make coverage      tests under coverage.py -> reports/coverage/coverage.xml"
	@echo "make image         build the app image locally"
	@echo "make compose-up    mariadb + redis + the app at http://localhost:8000"

lint:
	uv run --no-project --with ruff==0.14.4 ruff check frappe_gates_demo tests

test:
	cd $(BENCH) && bench --site $(SITE) run-tests --app frappe_gates_demo

test-junit:
	mkdir -p reports/unit-tests
	cd $(BENCH) && bench --site $(SITE) run-tests --app frappe_gates_demo \
		--junit-xml-output $(CURDIR)/reports/unit-tests/junit.xml

coverage:
	mkdir -p reports/coverage
	cd $(BENCH)/sites && ../env/bin/coverage run --rcfile=$(CURDIR)/.coveragerc \
		-m frappe.utils.bench_helper frappe --site $(SITE) run-tests --app frappe_gates_demo
	cd $(BENCH)/sites && ../env/bin/coverage xml -o $(CURDIR)/reports/coverage/coverage.xml -q
	cd $(BENCH)/sites && ../env/bin/coverage report

image:
	docker build --provenance=false --sbom=false -t frappe-gates-demo:local .

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down -v

clean:
	rm -rf reports .ruff_cache .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
