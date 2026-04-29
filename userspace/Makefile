CC     = gcc
CFLAGS = -Wall -Wextra -I../include
TARGET = sealant

all: $(TARGET)

$(TARGET): sealant.c sealant_migrate.c sealant_parse.c sealant_comm.c
	$(CC) $(CFLAGS) -o $(TARGET) sealant.c sealant_migrate.c sealant_parse.c sealant_comm.c

install: $(TARGET)
	sudo ln -sf $(shell pwd)/$(TARGET) /usr/local/bin/sealant
	sudo mkdir -p /etc/sealant
	@echo "sealant installed"

uninstall:
	sudo rm -f /usr/local/bin/sealant
	@echo "sealant uninstalled"

clean:
	rm -f $(TARGET)
