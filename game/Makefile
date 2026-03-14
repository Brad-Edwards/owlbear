# Owlbear test game — target application for anti-cheat testing

TARGET   := owlbear-game

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -Wpedantic \
            -D_GNU_SOURCE -no-pie \
            $(INCLUDES) $(CFLAGS_EXTRA)
LDFLAGS  := -no-pie -lncurses -lm
DEPFLAGS  = -MMD -MP -MF $(@:.o=.d)

SRCS     := main.c
OBJS     := $(SRCS:.c=.o)
DEPS     := $(SRCS:.c=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
