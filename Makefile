init:
	python3.13 -m venv .venv
	pre-commit install
	pip install -r requirements.txt
