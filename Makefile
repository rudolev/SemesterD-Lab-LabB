# Variables
CC = gcc
CFLAGS = -m32 -g -Wall
TARGET = antivirus
SRC = antivirus.c

# Default target
all: $(TARGET)

# Link and compile antivirus
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

# Clean up build files
clean:
	rm -f $(TARGET)

# Phony targets
.PHONY: all clean