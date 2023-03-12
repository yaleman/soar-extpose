.PHONY: build
.DEFAULT: build

build:
	tar czvf Extpose.tgz phExtpose/

test:
	poetry run ruff phExtpose
	poetry run mypy phExtpose
	poetry run pytest
