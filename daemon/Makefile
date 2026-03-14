# Owlbear daemon — userspace event processor
#
# Builds: owlbeard (the daemon binary)

TARGET   := owlbeard

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -Wpedantic \
            -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 \
            $(INCLUDES) $(CFLAGS_EXTRA)
LDFLAGS  := -lpthread -lcurl
DEPFLAGS  = -MMD -MP -MF $(@:.o=.d)

# Source files (add as components are built)
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
