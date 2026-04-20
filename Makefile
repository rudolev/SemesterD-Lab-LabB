CC = gcc
CFLAGS = -m32 -g -Wall
TARGET = antivirus
SRC = antivirus.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean