#!/bin/bash

valgrind="valgrind --leak-check=full --show-leak-kinds=all ./server "
outspace="echo -e '\n\n\n'"
memchk="eval "$outspace";"$valgrind

# Try no arguments
$memchk 

# Invalid port number 
$memchk 77777 t 5

# Invalid trust mode (TO BE IMPLEMENTED)

# Valid input
$memchk 12344 t 234


