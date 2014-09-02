.PHONY: all build rebuild clean

ifeq ($(DEBUG),1)
OPT_FLAGS = -g -DDEBUG
else
OPT_FLAGS = -g -O2 -DNDEBUG
endif

INCLUDES = -I../include

CXX = clang++
CFLAGS = -Wall -Wextra -D_FILE_OFFSET_BITS=64 $(OPT_FLAGS) $(INCLUDES)
CXXFLAGS = -std=c++11 $(CFLAGS)

LDFLAGS =
LDLIBS =

BINARIES = bdevtc
DEPENDS = $(patsubst %,%.depend,$(BINARIES))

all: build

build: $(BINARIES)

rebuild:
	$(MAKE) clean
	$(MAKE) all

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%: %.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f *.o *.depend $(BINARIES)

%.depend: %.cpp
	$(CXX) -MM $< $(CXXFLAGS) > $@

ifneq "$(MAKECMDGOALS)" "clean"
-include $(DEPENDS)
endif
