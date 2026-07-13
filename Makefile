.PHONY: setup backend dashboard train attack-ransom attack-mem attack-cpu test lint docker-up clean

setup:
	python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt
	cd dashboard && npm install

backend:
	sudo python3 -m uvicorn collector.main:app --reload --host 0.0.0.0 --port 8000

dashboard:
	cd dashboard && npm run dev

train:
	python3 -m ml.train

attack-ransom:
	python3 attacks/ransomware_sim.py

attack-mem:
	python3 attacks/memory_leak.py

attack-cpu:
	python3 attacks/cpu_hog.py 15

attack-fork:
	python3 attacks/fork_bomb_safe.py 6

test:
	pytest tests/ -v --tb=short

lint:
	flake8 collector/ ml/ probes/ --max-line-length=100 --ignore=E501,W503

docker-up:
	docker compose up --build

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	rm -f osmosis.db ml/models/*.pkl ml/models/*.pt ml/models/*.json
