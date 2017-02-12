#
# Makefile for Programming Project 1
#

CC  = gcc
CXX = g++

INCLUDES = -lbsd 
CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDFLAGS = 
LDLIBS  = -lbsd

.PHONY: default
default: client #server

client: client.o

.PHONY: clean
clean:
	rm -f *.o *~ *.out core client server

.PHONY: all
all: clean default

