.PHONY: install test eval eval-llm scan-stand sandbox-image
install:
	pip install -e '.[stand,dev]'
test:
	python -m pytest -q tests
eval:            ## deterministic rows of the ablation table
	python -m eval.run_eval
eval-llm:        ## + rows that need a model (configs/providers.yaml, .env with keys)
	python -m eval.run_eval --llm
scan-stand:
	caa scan eval/seeded/repo --own-stand --trust-target --out caa-out/stand
sandbox-image:
	docker build -t caa-sandbox:latest -f caa/sandbox/Dockerfile .
