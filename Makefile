SHELL := /bin/bash

CONTAINER ?= wg-easy
WG_IF     ?= wg0
VPN_CIDR  ?= 172.16.0.0/24
CHAIN     ?= WG_ISO
WL_FILE   ?= whitelist.txt

# Run a command inside the container (robust quoting).
# IMPORTANT: Always pass a single-line command in $(1). Use ';' to separate statements.
define docker_sh
docker exec -i $(CONTAINER) sh -lc "$(1)"
endef

.PHONY: help status iso-on iso-off iso-rebuild wl-list wl-add wl-del wl-apply

help:
	@echo "Targets:"
	@echo "  make status               - show current isolation status and chain rules"
	@echo "  make iso-on               - enable client isolation (wg0->wg0 restricted)"
	@echo "  make iso-off              - disable client isolation (remove chain/jump)"
	@echo "  make wl-list              - show whitelist file"
	@echo "  make wl-add IP=...        - add IP to whitelist file and apply"
	@echo "  make wl-del IP=...        - remove IP from whitelist file and apply"
	@echo "  make wl-apply             - apply whitelist to container (rebuild chain)"
	@echo ""
	@echo "Vars (optional):"
	@echo "  CONTAINER=$(CONTAINER)"
	@echo "  WG_IF=$(WG_IF)"
	@echo "  VPN_CIDR=$(VPN_CIDR)"
	@echo "  CHAIN=$(CHAIN)"
	@echo "  WL_FILE=$(WL_FILE)"

status:
	@echo "== Container: $(CONTAINER) =="
	@$(call docker_sh, "printf '%s\n' '--- interfaces ---'; ip -br link; echo; \
		printf '%s\n' '--- addresses ---'; ip -br addr; echo; \
		printf '%s\n' '--- routes ---'; ip route; echo; \
		printf '%s\n' '--- wg ---'; (wg show 2>/dev/null || true); echo; \
		printf '%s\n' '--- iptables FORWARD ---'; iptables -S FORWARD; echo; \
		printf '%s\n' '--- chain $(CHAIN) ---'; (iptables -S $(CHAIN) 2>/dev/null || printf '%s\n' 'chain not present')")

# Enable isolation: create/rebuild chain + ensure FORWARD jump exists.
iso-on: iso-rebuild
	@echo "Isolation enabled."

# Disable isolation completely: remove jump, flush+delete chain
iso-off:
	@echo "Disabling isolation..."
	@$(call docker_sh, "iptables -D FORWARD -i $(WG_IF) -o $(WG_IF) -j $(CHAIN) 2>/dev/null || true; \
		iptables -F $(CHAIN) 2>/dev/null || true; \
		iptables -X $(CHAIN) 2>/dev/null || true")
	@echo "Isolation disabled."

# Rebuild chain rules based on WL_FILE:
# Logic (only affects wg0->wg0 forwarding):
#   1) allow ESTABLISHED/RELATED
#   2) allow destinations in whitelist.txt
#   3) drop all other wg0->wg0 (client->client not in whitelist)
iso-rebuild:
	@echo "Rebuilding isolation rules from $(WL_FILE)..."
	@[ -f "$(WL_FILE)" ] || (echo "ERROR: $(WL_FILE) not found. Create it first."; exit 1)

	@# 1) Ensure chain exists
	@$(call docker_sh, "iptables -N $(CHAIN) 2>/dev/null || true")

	@# 2) Ensure jump exists at the TOP for wg0->wg0 only
	@$(call docker_sh, "iptables -C FORWARD -i $(WG_IF) -o $(WG_IF) -j $(CHAIN) 2>/dev/null || \
		iptables -I FORWARD 1 -i $(WG_IF) -o $(WG_IF) -j $(CHAIN)")

	@# 3) Flush chain and add base allow for established/related
	@$(call docker_sh, "iptables -F $(CHAIN); \
		iptables -A $(CHAIN) -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

	@# 4) Add whitelist destination rules (host-side loop, apply inside container)
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
	@$(call docker_sh, "iptables -A $(CHAIN) -j DROP")

	@echo "Isolation rules rebuilt."

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