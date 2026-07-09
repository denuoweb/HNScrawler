.PHONY: install test lint fixture-site verify-release clean

install:
	python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip && pip install -e '.[dev]'

test:
	. .venv/bin/activate && pytest

lint:
	. .venv/bin/activate && ruff check .

fixture-site:
	rm -rf data public
	. .venv/bin/activate && hns-topology bootstrap-fixture --fixture tests/fixtures/sample_hsd_names.json --db data/topology.sqlite
	. .venv/bin/activate && hns-topology discover-hosts --db data/topology.sqlite
	. .venv/bin/activate && hns-topology generate-site --db data/topology.sqlite --out public

verify-release:
	. .venv/bin/activate && hns-topology validate-release --db data/topology.sqlite --public-dir public

clean:
	rm -rf data public .pytest_cache .ruff_cache
