CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto

# Source paths
SUPERVISOR_DIR = ../supervisor
USER_TOOL_DIR = ../user-tool
DEMO_DIR = ../demo

# Targets with paths
TARGETS = \
	$(SUPERVISOR_DIR)/supervisor \
	$(USER_TOOL_DIR)/user-tool \
	$(DEMO_DIR)/test-server \
	$(DEMO_DIR)/test-client

# Default target
all: $(TARGETS)

# Build rules with explicit paths
$(SUPERVISOR_DIR)/supervisor: $(SUPERVISOR_DIR)/supervisor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(USER_TOOL_DIR)/user-tool: $(USER_TOOL_DIR)/user-tool.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(DEMO_DIR)/test-server: $(DEMO_DIR)/test-server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(DEMO_DIR)/test-client: $(DEMO_DIR)/test-client.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Clean rule with path-aware removal
clean:
	rm -f $(TARGETS) $(DEMO_DIR)/*.o $(USER_TOOL_DIR)/*.o $(SUPERVISOR_DIR)/*.o

# Modified test rule with path references
test: all
	@echo "Starting test sequence..."
	$(USER_TOOL_DIR)/user-tool & 
	sleep 1
	$(DEMO_DIR)/test-server &
	sleep 1
	$(SUPERVISOR_DIR)/supervisor $(DEMO_DIR)/test-client
	pkill -f "$(DEMO_DIR)/test-server"
	pkill -f "$(USER_TOOL_DIR)/user-tool"

.PHONY: all clean test