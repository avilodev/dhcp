# DHCP server — build and install.
#
# Usage:
#   make                 # build bin/dhcp_server and generate misc/dhcp.conf
#   sudo make install    # build + install cron jobs (@reboot startup + nightly maintenance)
#   sudo make uninstall  # remove the installed cron jobs
#   make clean           # remove build artifacts
#   make rebuild         # clean + build

CC      = gcc
# -fstack-protector-strong + -D_FORTIFY_SOURCE=2: buffer-overflow hardening.
# -MMD -MP: emit .d files so header edits trigger the right recompiles.
CFLAGS  = -Wall -Wextra -O2 -g -Isrc -MMD -MP \
          -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS = -pthread

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SOURCES = main.c trie.c node.c config.c response.c request.c lease.c utils.c
OBJECTS = $(addprefix $(OBJ_DIR)/, $(SOURCES:.c=.o))
TARGET  = $(BIN_DIR)/dhcp_server

# Everything below is derived from this checkout — no path or username is baked
# in, so cloning to any location / user just works (same approach as ../dns).
PREFIX       := $(CURDIR)
CRON_D       := /etc/cron.d
STARTUP_SRC  := $(PREFIX)/cron_scripts/dhcp-startup
STARTUP_CRON := $(CRON_D)/dhcp-startup
MAINT_SRC    := $(PREFIX)/misc/maintence.sh
MAINT_CRON   := $(CRON_D)/dhcp-maintenance
REFRESH_LOG  := $(PREFIX)/misc/refresh.log

.PHONY: all clean rebuild install uninstall

all: configure $(TARGET)

# Link.
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile.
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR) $(BIN_DIR):
	@mkdir -p $@

# Pull in auto-generated header dependencies.
-include $(OBJECTS:.o=.d)

# Generate misc/dhcp.conf from the template, stamping in this directory.
# Re-run (or touch the template) if you move the project.
configure: misc/dhcp.conf
misc/dhcp.conf: misc/dhcp.conf.in
	sed 's|@PREFIX@|$(PREFIX)|g' $< > $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Clean complete"

rebuild: clean all

# Build, then install two cron jobs into /etc/cron.d (needs root):
#   dhcp-startup      @reboot — starts the server at boot via the in-repo launcher
#   dhcp-maintenance  nightly — prunes leases, rotates the log, trims old backups
install: all
	@chmod 755 $(STARTUP_SRC) $(MAINT_SRC)
	@printf '%s\n%s\n%s\n' \
	    '# Start the DHCP server at boot. Edit the launcher to change how it runs:' \
	    '#   $(STARTUP_SRC)' \
	    '@reboot root $(STARTUP_SRC)' \
	    > $(STARTUP_CRON)
	@chmod 644 $(STARTUP_CRON)
	@printf '%s\n%s\n' \
	    '# Nightly DHCP maintenance: prune expired leases, rotate log, clean backups.' \
	    '0 3 * * * root $(MAINT_SRC) >> $(REFRESH_LOG) 2>&1' \
	    > $(MAINT_CRON)
	@chmod 644 $(MAINT_CRON)
	@echo ""
	@echo "Installed cron jobs:"
	@echo "  $(STARTUP_CRON)       @reboot     -> $(STARTUP_SRC)"
	@echo "  $(MAINT_CRON)   nightly 03:00 -> $(MAINT_SRC)"
	@echo ""
	@echo "Reboot to start the server automatically, or launch it now with:"
	@echo "  sudo $(STARTUP_SRC)"

uninstall:
	rm -f $(STARTUP_CRON) $(MAINT_CRON)
	@echo "Removed cron jobs: dhcp-startup, dhcp-maintenance"
