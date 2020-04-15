CC?=gcc
CFLAGS+=-lelf -lpopt -Wall
SOURCES=obfuscateElfStr.c hashtab.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=obfuscateElfStr

all: $(SOURCES) $(EXECUTABLE)
clean: 
	rm -f $(OBJECTS) *.exe $(EXECUTABLE)
	
$(EXECUTABLE): $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(CFLAGS) 
