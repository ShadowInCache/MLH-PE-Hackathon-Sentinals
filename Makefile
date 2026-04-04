.PHONY: chaos-kill-app1 chaos-kill-app2 chaos-stop-redis chaos-stop-postgres chaos-spike-errors chaos-reset quarantine-demo

chaos-kill-app1:
	docker compose stop app1

chaos-kill-app2:
	docker compose stop app2

chaos-stop-redis:
	docker compose stop redis

chaos-stop-postgres:
	docker compose stop postgres

chaos-spike-errors:
	@echo "Generating invalid and blocked request spikes..."
	@i=1; while [ $$i -le 120 ]; do \
		curl -s -o /dev/null "http://localhost/invalid-$$i"; \
		i=$$((i+1)); \
	done
	@./scripts/quarantine_code.sh chaos-demo
	@i=1; while [ $$i -le 60 ]; do \
		curl -s -o /dev/null "http://localhost/chaos-demo"; \
		i=$$((i+1)); \
	done

chaos-reset:
	docker compose start app1 app2 redis postgres
	docker compose restart nginx canary-runner security-exporter
	./scripts/unquarantine_code.sh chaos-demo || true

quarantine-demo:
	./scripts/quarantine_code.sh demo-threat
