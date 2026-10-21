# DHCP server — build and install.
#
# Usage:
#   make                 # build bin/dhcp_server (and create config/dhcp.conf if missing)
#   make config-diff     # compare your config/dhcp.conf with the current template
#   sudo make install    # build + install cron jobs (@reboot startup + nightly maintenance)
#   sudo make uninstall  # remove the installed cron jobs
#   make clean           # remove build artifacts
#   make rebuild         # clean + build
#   make peer-key        # create config/peer.key (cluster mode) if it doesn't exist
#   make instance ID=A2 [PEER_PORT=648] [CONTROLLER=192.168.1.4] [ROLE=controller]
#                        # add another cluster node (or the controller) on this
#                        # machine, sharing its address (etc/instances/A2)
#   make test            # build + run the end-to-end tests (no sudo needed)

# Every path and the run user are derived from this checkout — nothing is
# baked into the source, so cloning to any location / user just works (same
# approach as ../dns):
#   PREFIX     this directory; compiled in as SERVER_PATH (the defaults for
#              every runtime file) and stamped into the generated configs
#   RUN_USER   the checkout's owner: the server drops to it after binding
#   RUN_GROUP  port 67, nightly maintenance runs as it, and `sudo make` hands
#              build output and runtime files back to it
PREFIX    := $(CURDIR)
RUN_USER  := $(shell stat -c '%U' '$(PREFIX)')
RUN_GROUP := $(shell stat -c '%G' '$(PREFIX)')

CC      = gcc
# -fstack-protector-strong + -D_FORTIFY_SOURCE=2: buffer-overflow hardening.
# -MMD -MP: emit .d files so header edits trigger the right recompiles.
CFLAGS  = -Wall -Wextra -O2 -g -Isrc -MMD -MP \
          -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
          -DSERVER_PATH='"$(PREFIX)"'
LDFLAGS = -pthread -lcrypto

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SOURCES = main.c trie.c node.c config.c response.c request.c lease.c utils.c \
          journal.c ha.c peer.c cluster.c probe.c
OBJECTS = $(addprefix $(OBJ_DIR)/, $(SOURCES:.c=.o))
TARGET  = $(BIN_DIR)/dhcp_server

CRON_D       := /etc/cron.d
STARTUP_SRC  := $(PREFIX)/scripts/dhcp-startup
STARTUP_CRON := $(CRON_D)/dhcp-startup
MAINT_SRC    := $(PREFIX)/scripts/maintenance.sh
MAINT_CRON   := $(CRON_D)/dhcp-maintenance
REFRESH_LOG  := $(PREFIX)/etc/refresh.log

PEER_KEY     := $(PREFIX)/config/peer.key

.PHONY: all configure config-diff owner clean rebuild install uninstall peer-key test instance FORCE

all: configure $(TARGET) owner

# Recompile when the checkout moves: the objects have PREFIX compiled in, and
# this stamp changes only when PREFIX does.
PATH_STAMP := $(OBJ_DIR)/.prefix
$(PATH_STAMP): FORCE | $(OBJ_DIR)
	@echo '$(PREFIX)' | cmp -s - $@ || echo '$(PREFIX)' > $@
FORCE:

# Link.
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile.
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(PATH_STAMP) | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

# Pull in auto-generated header dependencies.
-include $(OBJECTS:.o=.d)

# Create config/dhcp.conf from the template (stamping in this directory) — but
# only if it doesn't exist.  Once it's there it's YOUR file: `make` never
# overwrites it.  If the template has gained new options since, it says so and
# `make config-diff` shows what's new.
CONF      := config/dhcp.conf
CONF_IN   := config/dhcp.conf.in
CONF_SED  := sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@RUN_USER@|$(RUN_USER)|g'
configure:
	@if [ ! -f $(CONF) ]; then \
	    $(CONF_SED) $(CONF_IN) > $(CONF) && \
	    echo "Created $(CONF) from the template — edit it for your network"; \
	elif ! $(CONF_SED) $(CONF_IN) | cmp -s - $(CONF) && \
	     [ $(CONF_IN) -nt $(CONF) ]; then \
	    echo "Note: $(CONF_IN) changed since your $(CONF) was made; your config was"; \
	    echo "      left alone.  See what's new with: make config-diff"; \
	fi

# What the template would give you, compared with your current config
config-diff:
	@$(CONF_SED) $(CONF_IN) | diff -u $(CONF) - || true

# Under sudo, hand the build output and runtime files back to RUN_USER so they
# can be read, rebuilt and deleted without sudo.  -h: never follow a symlink.
owner: configure $(TARGET)
	@if [ "$$(id -u)" -eq 0 ]; then \
	    chown -R -h $(RUN_USER):$(RUN_GROUP) $(OBJ_DIR) $(BIN_DIR) config etc; \
	fi

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Clean complete"

rebuild: clean all

# Shared secret for the cluster peer link.  Create it once, then copy the SAME
# file to every node and the controller (e.g. with scp).  Never overwritten.
peer-key:
	@if [ -e $(PEER_KEY) ]; then \
	    echo "$(PEER_KEY) already exists — not touching it"; \
	else \
	    umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > $(PEER_KEY) && \
	    echo >> $(PEER_KEY) && \
	    echo "Created $(PEER_KEY) — copy this exact file to every cluster member"; \
	fi

# Another DHCP cluster node on THIS machine.  It shares the machine's address
# (IP= only if you want a separate one) and gets its own peer port.  Prints the
# remaining steps (cluster.conf line, start).
instance:
	@[ -n "$(ID)" ] || { echo "usage: make instance ID=A2 [PEER_PORT=648] [CONTROLLER=192.168.1.4] [ROLE=controller] [IP=...]"; exit 1; }
	@RUN_USER=$(RUN_USER) bash $(PREFIX)/scripts/new-instance.sh "$(ID)" "$(IP)" "$(PEER_PORT)" "$(CONTROLLER)" "$(ROLE)"

# End-to-end tests in throwaway network namespaces (see tests/harness.py)
test: $(TARGET)
	python3 tests/run_tests.py $(TARGET)

# Build, then install two cron jobs into /etc/cron.d (needs root):
#   dhcp-startup      @reboot + every 5 min — starts the server at boot, and
#                     restarts it if it has died, via the in-repo launcher
#   dhcp-maintenance  nightly, as RUN_USER (it needs no root) — rotates the log,
#                     backs up leases, trims old backups; everything it writes
#                     stays readable and deletable without sudo
# The launcher logs what it does to server.log itself; its stdout ("already
# running") is dropped and anything on stderr lands in refresh.log.
install: all
	@chmod 755 $(STARTUP_SRC) $(MAINT_SRC)
	@printf '%s\n%s\n%s\n%s\n%s\n' \
	    '# Start the DHCP server at boot, and restart it within 5 minutes if it dies.' \
	    '# Edit the launcher to change how it runs:' \
	    '#   $(STARTUP_SRC)' \
	    '@reboot     root $(STARTUP_SRC) > /dev/null 2>> $(REFRESH_LOG)' \
	    '*/5 * * * * root $(STARTUP_SRC) > /dev/null 2>> $(REFRESH_LOG)' \
	    > $(STARTUP_CRON)
	@chmod 644 $(STARTUP_CRON)
	@printf '%s\n%s\n' \
	    '# Nightly DHCP maintenance: archive server.log, back up leases, trim old backups.' \
	    '0 3 * * * $(RUN_USER) $(MAINT_SRC) >> $(REFRESH_LOG) 2>&1' \
	    > $(MAINT_CRON)
	@chmod 644 $(MAINT_CRON)
	@echo ""
	@echo "Installed cron jobs:"
	@echo "  $(STARTUP_CRON)       @reboot + every 5 min -> $(STARTUP_SRC)"
	@echo "  $(MAINT_CRON)   nightly 03:00 as $(RUN_USER) -> $(MAINT_SRC)"
	@echo ""
	@echo "Reboot to start the server automatically, or launch it now with:"
	@echo "  sudo $(STARTUP_SRC)"

uninstall:
	rm -f $(STARTUP_CRON) $(MAINT_CRON)
	@echo "Removed cron jobs: dhcp-startup, dhcp-maintenance"
