.PHONY: test run-server run-agent-once lint

test:
	python3 -m pytest

run-server:
	cd server && python3 -m openeyes --host 0.0.0.0 --port 8080 --data-dir ./.openeyes-data

run-agent-once:
	cd agent && python3 -m openeyes_agent --server http://127.0.0.1:8080 --enroll-token $(TOKEN) --once
