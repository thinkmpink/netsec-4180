#!/bin/bash

valgrind="valgrind --leak-check=full --show-leak-kinds=all ./server "
outspace="echo -e '\n\n\n'"
memchk="eval "$outspace";"$valgrind

# Try no arguments
$memchk 

# Invalid trust mode
$memchk 12344 ur 44
$memchk 12344 tr 44

# Invalid port number 
$memchk 77777 t 5

# Invalid trust mode (TO BE IMPLEMENTED)

# Valid input
$memchk 12344 t 234


