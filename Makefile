GO?=go

PROG=go-blackhole
SOURCEDIR=.

SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

$(PROG): $(SOURCES)
	$(GO) build -o $@

.PHONY: clean
clean:
	rm -f $(PROG)
