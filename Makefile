# HA Security Sandbox — Build & Publish
#
# Usage:
#   make publish     Full chain: main → lint/test → publish → full check → deploy → github
#   make push        Push to main only (lint + test gate)
#   make status      Check latest pipeline status
#   make logs        Show running container logs

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

GITLAB_PROJECT = jiwanus%2Fha-sandbox
POLL_INTERVAL = 10

# ---------------------------------------------------------------------------
# publish: full chain — main → CI → publish → CI → github
# ---------------------------------------------------------------------------
.PHONY: publish
publish:
	@set -e; \
	echo "══════════════════════════════════════════════════"; \
	echo "  STEP 1/4: Push to main (GitLab)"; \
	echo "══════════════════════════════════════════════════"; \
	git push origin main; \
	SHA=$$(git rev-parse HEAD); \
	\
	echo ""; \
	echo "══════════════════════════════════════════════════"; \
	echo "  STEP 2/4: Waiting for main pipeline (lint+test)"; \
	echo "══════════════════════════════════════════════════"; \
	$(MAKE) --no-print-directory _wait_sha SHA=$$SHA; \
	\
	echo ""; \
	echo "══════════════════════════════════════════════════"; \
	echo "  STEP 3/4: Fast-forward publish → main"; \
	echo "══════════════════════════════════════════════════"; \
	git fetch origin; \
	git branch -f publish origin/main; \
	git push origin publish --force; \
	\
	echo ""; \
	echo "══════════════════════════════════════════════════"; \
	echo "  STEP 4/4: Waiting for publish pipeline"; \
	echo "           (lint+test+security+build+deploy+github)"; \
	echo "══════════════════════════════════════════════════"; \
	$(MAKE) --no-print-directory _wait_sha SHA=$$SHA REF=publish; \
	\
	echo ""; \
	echo "══════════════════════════════════════════════════"; \
	echo "  DONE — deployed and mirrored to GitHub"; \
	echo "══════════════════════════════════════════════════"

# ---------------------------------------------------------------------------
# push: just push to main (lint + test only)
# ---------------------------------------------------------------------------
.PHONY: push
push:
	@set -e; \
	git push origin main; \
	SHA=$$(git rev-parse HEAD); \
	$(MAKE) --no-print-directory _wait_sha SHA=$$SHA

# ---------------------------------------------------------------------------
# status: show latest pipelines
# ---------------------------------------------------------------------------
.PHONY: status
status:
	@glab api /projects/$(GITLAB_PROJECT)/pipelines 2>/dev/null | \
		python3 -c "import json,sys; ps=json.load(sys.stdin)[:5]; [print(f'#{p[\"iid\"]:3}  {p[\"ref\"]:10}  {p[\"status\"]:10}  {p[\"created_at\"][:19]}') for p in ps]"

# ---------------------------------------------------------------------------
# logs: container logs
# ---------------------------------------------------------------------------
.PHONY: logs
logs:
	ssh nas00 '/share/ZFS530_DATA/.qpkg/container-station/bin/docker logs ha-sandbox --tail 30'

# ---------------------------------------------------------------------------
# Internal: wait for pipeline matching SHA (and optionally REF)
# ---------------------------------------------------------------------------
.PHONY: _wait_sha
_wait_sha:
	@set -e; \
	PIPE_ID=""; \
	echo "Waiting for pipeline (sha=$(SHA)$(if $(REF), ref=$(REF)))..."; \
	for i in $$(seq 1 30); do \
		PIPE_ID=$$(glab api "/projects/$(GITLAB_PROJECT)/pipelines?sha=$(SHA)&per_page=10" 2>/dev/null | \
			python3 -c "import json,sys; ps=json.load(sys.stdin); ref='$(REF)'; ps=[p for p in ps if not ref or p['ref']==ref]; print(ps[0]['id'] if ps else '')" 2>/dev/null) || true; \
		if [ -n "$$PIPE_ID" ]; then break; fi; \
		printf "\r  waiting for pipeline to start... (%d/30) " "$$i"; \
		sleep 3; \
	done; \
	if [ -z "$$PIPE_ID" ]; then echo ""; echo "ERROR: no pipeline found for SHA=$(SHA)"; exit 1; fi; \
	echo "Pipeline $$PIPE_ID started"; \
	while true; do \
		STATUS=$$(glab api /projects/$(GITLAB_PROJECT)/pipelines/$$PIPE_ID 2>/dev/null | \
			python3 -c "import json,sys; print(json.load(sys.stdin)['status'])" 2>/dev/null) || true; \
		case "$$STATUS" in \
			success|manual) \
				echo "Pipeline $$PIPE_ID: $$STATUS"; \
				glab api /projects/$(GITLAB_PROJECT)/pipelines/$$PIPE_ID/jobs 2>/dev/null | \
					python3 -c "import json,sys; jobs=json.load(sys.stdin); jobs.sort(key=lambda j:j['id']); [print(f'  {j[\"name\"]:20} {j[\"status\"]:10} {(j.get(\"duration\") or 0):5.1f}s') for j in jobs]"; \
				break;; \
			failed) \
				echo "Pipeline $$PIPE_ID: FAILED"; \
				glab api /projects/$(GITLAB_PROJECT)/pipelines/$$PIPE_ID/jobs 2>/dev/null | \
					python3 -c "import json,sys; jobs=json.load(sys.stdin); jobs.sort(key=lambda j:j['id']); [print(f'  {j[\"name\"]:20} {j[\"status\"]:10}') for j in jobs]"; \
				exit 1;; \
			canceled) \
				echo "Pipeline $$PIPE_ID: CANCELED"; exit 1;; \
			*) \
				printf "\r  waiting... ($$STATUS)  "; \
				sleep $(POLL_INTERVAL);; \
		esac; \
	done
