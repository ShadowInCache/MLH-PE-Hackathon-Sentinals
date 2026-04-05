.PHONY: chaos-kill-app1 chaos-kill-app2 chaos-stop-redis chaos-stop-postgres chaos-spike-errors chaos-reset quarantine-demo rollback-app1 rollback-app2 rollback-all rollback-plan-app1 rollback-plan-app2 rollback-plan-all

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

rollback-app1:
	./scripts/rollback.sh app1

rollback-app2:
	./scripts/rollback.sh app2

rollback-all:
	./scripts/rollback.sh all

rollback-plan-app1:
	./scripts/rollback.sh --dry-run app1

rollback-plan-app2:
	./scripts/rollback.sh --dry-run app2

rollback-plan-all:
	./scripts/rollback.sh --dry-run all
