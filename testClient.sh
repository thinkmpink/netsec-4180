#!/bin/bash

# Run this once when server is not running, and again when it is
# Try random times to close server while client attempts to connect
# (there should be a good way of doing this)

valgrind="valgrind --leak-check=full --show-leak-kinds=all ./client "
outspace="echo -e '\n\n\n'"
memchk="eval "$outspace";"$valgrind

# Try no args, server should not die
$memchk

# Try invalid password (wrong length)
$memchk 23efjknj ./client.c localhost 12344 key_cli.pem key_serv.pub.pem

# Try invalid password (wrong type)
$memchk 234r23-*34de344f ./client.c localhost 12344 key_cli.pem key_serv.pub.pem

# Try invalid PT file name
$memchk 239r0f8hu2ijk3ej ./client.cpp localhost 12344 key_cli.pem key_serv.pub.pem

# Try invalid server IP address 
$memchk 123d90j84u58fnnw ./client.c 1234.55.6.88 12344 key_cli.pem key_serv.pub.pem

# Try invalid server port number
$memchk 8345yghbfu4renjh ./client.c localhost 72344 key_cli.pem key_serv.pub.pem

# Valid everything (server dies)
$memchk 2083rgf724ryfh3i ./client.c localhost 12344 key_cli.pem key_serv.pub.pem
