TARGET = ip_lookup

all: $(TARGET)

SRCS = tree.c util.c main.c

$(TARGET): $(SRCS)
	gcc -Wall -O2 -g $(SRCS) -o $(TARGET) -I./include

clean:
	@rm $(TARGET)
