# 
# Michael Pinkham - Author
# Makefile for Programming Project 1
#

CC  = gcc
CXX = g++

INCLUDES = -lbsd #-llibexplain
CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDFLAGS = 
LDLIBS  = -lbsd #-llibexplain

.PHONY: default
default: client server

client: client.o

server: server.o

.PHONY: clean
clean:
	rm -f *.o *~ *.out core client server

.PHONY: all
all: clean default

