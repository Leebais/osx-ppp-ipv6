# Makefile for RA sniffer on macOS

CC      = clang
CFLAGS  = CFLAGS = -Wall -O2 -s
LDFLAGS = -lpcap

TARGET  = ra_sniffer
SRC     = ra_sniffer.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC)
    $(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

install: $(TARGET)
    @echo "Installing $(TARGET) to /usr/local/bin..."
    @sudo cp $(TARGET) /usr/local/bin/$(TARGET)
    @sudo chmod 755 /usr/local/bin/$(TARGET)

clean:
    rm -f $(TARGET) *.o
