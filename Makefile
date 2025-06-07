CC = gcc
CFLAGS = -std=c99 -Wall -Wextra -g -Wno-enum-conversion -Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-unused-parameter -Wno-format-truncation -Wno-sign-compare -Wno-overflow
QUIET_FLAG = -DQUIET_MODE
INCLUDES = -Iinclude

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SOURCES))
TARGET = $(BIN_DIR)/nas

# Ensure necessary directories exist
$(shell mkdir -p $(OBJ_DIR) $(BIN_DIR))

# Default target
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)/* $(BIN_DIR)/* test/*.bin test/floppy.img

test_asm:
	bin/nas -m32 -f bin test/test.asm -o test/floppy.img

.PHONY: all clean test_asm
