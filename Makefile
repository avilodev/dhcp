CC = gcc
# -MMD -MP: generate .d dependency files so header changes trigger recompilation
# -fstack-protector-strong: stack-smashing protection on functions with buffers
# -D_FORTIFY_SOURCE=2: glibc buffer-overflow detection for string/mem functions
CFLAGS  = -Wall -Wextra -O2 -g -Isrc \
          -MMD -MP \
          -fstack-protector-strong \
          -D_FORTIFY_SOURCE=2
LDFLAGS = -pthread

# Directories
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# Source files (just the names)
SOURCES = main.c trie.c node.c config.c response.c request.c lease.c utils.c 

# Full paths
SRC_FILES = $(addprefix $(SRC_DIR)/, $(SOURCES))
OBJECTS = $(addprefix $(OBJ_DIR)/, $(SOURCES:.c=.o))

TARGET = $(BIN_DIR)/dhcp_server

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Link object files into executable
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Include auto-generated header dependency files (produced by -MMD -MP)
-include $(OBJECTS:.o=.d)

# Compile source files to object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Clean complete"

# Rebuild from scratch
rebuild: clean all

# Run the server
run: $(TARGET)
	sudo ./$(TARGET)

# Debugging info
debug:
	@echo "Sources: $(SRC_FILES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"

.PHONY: all clean rebuild run debug directories
