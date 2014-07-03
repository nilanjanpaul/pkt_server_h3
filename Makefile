NAME := pkt_server
CC  := g++
SRCS := $(wildcard *.cpp)
OBJS := ${SRCS:.cpp=.o}
INCLUDE_DIRS :=
LIBRARY_DIRS :=
LIBRARIES := boost_system-mt boost_random-mt boost_thread-mt boost_program_options-mt boost_iostreams-mt log4cxx oml2

CPPFLAGS += $(foreach includedir,$(INCLUDE_DIRS),-I$(includedir))
CPPFLAGS += -Wall -g -O
LDFLAGS += $(foreach librarydir,$(LIBRARY_DIRS),-L$(librarydir))
LDLIBS += $(foreach library,$(LIBRARIES),-l$(library))

.PHONY: all clean

$(NAME): $(OBJS) 
	g++ $(LDFLAGS) $(OBJS) -o $(NAME) $(LDLIBS)

all: ${NAME}

clean:
	@- rm -rf $(OBJS) $(NAME)
