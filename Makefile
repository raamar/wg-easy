SHELL := /bin/bash

CONTAINER ?= wg-easy
WG_IF     ?= wg0
CHAIN     ?= WG_ISO
WL_FILE   ?= whitelist.txt

.PHONY: help status iso-on iso-off iso-rebuild wl-list wl-add wl-del wl-apply iso-check

help:
	@echo "Targets:"
	@echo "  make status               - show isolation status (iptables only, no peers)"
	@echo "  make iso-on               - enable client isolation (wg0->wg0 restricted)"
	@echo "  make iso-off              - disable client isolation (remove chain/jump)"
	@echo "  make wl-list              - show whitelist file"
	@echo "  make wl-add IP=...        - add IP to whitelist file and apply"
	@echo "  make wl-del IP=...        - remove IP from whitelist file and apply"
	@echo "  make wl-apply             - apply whitelist to container (rebuild chain)"
	@echo "  make iso-check            - verify jump/chain + show allowed IPs from iptables"
	@echo ""
	@echo "Vars (optional): CONTAINER=$(CONTAINER) WG_IF=$(WG_IF) CHAIN=$(CHAIN) WL_FILE=$(WL_FILE)"

# Status: only iptables + container interfaces, no wg peers
status:
	@echo "== Container: $(CONTAINER) =="
	@docker exec -i $(CONTAINER) sh -lc ' \
		printf "%s\n" "--- interfaces (container) ---"; ip -br link; echo; \
		printf "%s\n" "--- iptables policies ---"; iptables -S | sed -n "1,3p"; echo; \
		printf "%s\n" "--- FORWARD rules ---"; iptables -S FORWARD; echo; \
		printf "%s\n" "--- isolation chain: $(CHAIN) ---"; (iptables -S $(CHAIN) 2>/dev/null || printf "%s\n" "chain not present"); \
	'

iso-on: iso-rebuild
	@echo "Isolation enabled."

iso-off:
	@echo "Disabling isolation..."
	@docker exec -i $(CONTAINER) sh -lc ' \
		iptables -D FORWARD -i $(WG_IF) -o $(WG_IF) -j $(CHAIN) 2>/dev/null || true; \
		iptables -F $(CHAIN) 2>/dev/null || true; \
		iptables -X $(CHAIN) 2>/dev/null || true; \
	'
	@echo "Isolation disabled."

# Rebuild chain based on WL_FILE (destination whitelist only for wg0->wg0)
iso-rebuild:
	@echo "Rebuilding isolation rules from $(WL_FILE)..."
	@[ -f "$(WL_FILE)" ] || (echo "ERROR: $(WL_FILE) not found. Create it first."; exit 1)

	@# 1) Ensure chain exists
	@docker exec -i $(CONTAINER) sh -lc 'iptables -N $(CHAIN) 2>/dev/null || true'

	@# 2) Ensure jump exists at the TOP for wg0->wg0 only
	@docker exec -i $(CONTAINER) sh -lc ' \
		iptables -C FORWARD -i $(WG_IF) -o $(WG_IF) -j $(CHAIN) 2>/dev/null || \
		iptables -I FORWARD 1 -i $(WG_IF) -o $(WG_IF) -j $(CHAIN); \
	'

	@# 3) Flush chain and add established/related allow
	@docker exec -i $(CONTAINER) sh -lc ' \
		iptables -F $(CHAIN); \
		iptables -A $(CHAIN) -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; \
	'

	@# 4) Add whitelist destination rules
	@set -euo pipefail; \
	while IFS= read -r line; do \
		raw="$${line}"; \
		ip="$${raw%%#*}"; \
		ip="$$(echo "$$ip" | xargs)"; \
		[ -z "$$ip" ] && continue; \
		if [[ ! "$$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$$ ]]; then \
			echo "Skipping invalid entry in $(WL_FILE): '$$raw'"; \
			continue; \
		fi; \
		docker exec -i $(CONTAINER) sh -lc "iptables -A $(CHAIN) -d $$ip/32 -j ACCEPT"; \
	done < "$(WL_FILE)"

	@# 5) Final drop for all remaining wg0->wg0
	@docker exec -i $(CONTAINER) sh -lc 'iptables -A $(CHAIN) -j DROP'

	@echo "Isolation rules rebuilt."

iso-check:
	@echo "== Isolation check =="
	@docker exec -i $(CONTAINER) sh -lc ' \
		printf "%s\n" "Jump present? (FORWARD wg0->wg0 -> $(CHAIN))"; \
		(iptables -C FORWARD -i $(WG_IF) -o $(WG_IF) -j $(CHAIN) 2>/dev/null && echo YES || echo NO); \
		echo; \
		printf "%s\n" "Allowed destinations in $(CHAIN):"; \
		(iptables -S $(CHAIN) 2>/dev/null | sed -n "s/^-A $(CHAIN) -d \\([0-9.]*\\)\\/32 -j ACCEPT$$/\\1/p" || true); \
		echo; \
		printf "%s\n" "Chain tail (should end with DROP):"; \
		(iptables -S $(CHAIN) 2>/dev/null | tail -n 5 || true); \
	'

wl-list:
	@echo "== $(WL_FILE) =="
	@[ -f "$(WL_FILE)" ] && cat "$(WL_FILE)" || echo "(missing)"

wl-add:
	@if [ -z "$${IP:-}" ]; then echo "Usage: make wl-add IP=172.16.0.10"; exit 1; fi
	@touch "$(WL_FILE)"
	@if grep -Eq "^[[:space:]]*$${IP}[[:space:]]*(#.*)?$$" "$(WL_FILE)"; then \
		echo "Already in whitelist: $$IP"; \
	else \
		echo "$$IP" >> "$(WL_FILE)"; \
		echo "Added: $$IP"; \
	fi
	@$(MAKE) wl-apply

wl-del:
	@if [ -z "$${IP:-}" ]; then echo "Usage: make wl-del IP=172.16.0.10"; exit 1; fi
	@[ -f "$(WL_FILE)" ] || (echo "No $(WL_FILE) to edit."; exit 1)
	@tmp="$$(mktemp)"; \
	awk -v ip="$$IP" '{ \
		line=$$0; \
		sub(/#.*/,"",line); \
		gsub(/^[ \t]+|[ \t]+$$/,"",line); \
		if (line!=ip) print $$0; \
	}' "$(WL_FILE)" > "$$tmp"; \
	mv "$$tmp" "$(WL_FILE)"; \
	echo "Removed (if existed): $$IP"
	@$(MAKE) wl-apply

wl-apply:
	@$(MAKE) iso-rebuild
	@echo "Whitelist applied."