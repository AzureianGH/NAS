CC = gcc
CFLAGS_COMMON = -std=c99 -Wall -Wextra -g \
	-Wno-enum-conversion -Wno-unused-but-set-variable \
	-Wno-unused-function -Wno-unused-variable \
	-Wno-unused-parameter -Wno-format-truncation \
	-Wno-sign-compare -Wno-overflow

QUIET_FLAG = -DQUIET_MODE
INCLUDES = -Iinclude

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))

# Ensure necessary directories exist
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR))

# Default target (build 64-bit)
all: build_64

# Build rules
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BIN_DIR)/nas32: CFLAGS := $(CFLAGS_COMMON) -m32
$(BIN_DIR)/nas32: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR)/nas64: CFLAGS := $(CFLAGS_COMMON) -m64
$(BIN_DIR)/nas64: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

# Aliases
build_32: $(BIN_DIR)/nas32
	@$(MAKE) clean_obj

build_64: $(BIN_DIR)/nas64
	@$(MAKE) clean_obj

clean:
	rm -rf $(OBJ_DIR)/* $(BIN_DIR)/* test/*.bin test/floppy.img

clean_obj:
	rm -rf $(OBJ_DIR)/*

.PHONY: all clean build_32 build_64 clean_obj
