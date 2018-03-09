
#!/usr/bin/make -f

CFLAGS += -Wall -Werror -Wextra -Os -std=c99 -pedantic

LDFLAGS := -lssl -lcrypto

.PHONY: all clean

all: imaps-watch

imaps-watch: ini.o

clean:
	$(RM) imaps-watch
	$(RM) *.o
