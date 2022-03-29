BINDIR := bin
SRCDIR := src

TARGET := aes-test

CFLAGS := -std=gnu99
CWARNS := -Wall -Wextra

all: $(BINDIR)/$(TARGET)

$(BINDIR)/$(TARGET): $(BINDIR) main.c aes.c aes.h
	@echo [$(CC)] $@
	@$(CC) -s $(CWARNS) $(CFLAGS) -o $@ main.c aes.c

$(BINDIR):
	@mkdir $(BINDIR)

clean:
	@echo [rm] $(BINDIR)
	@rm -rf $(BINDIR) 2> /dev/null || true

.PHONY: clean
