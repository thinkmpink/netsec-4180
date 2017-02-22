# Michael Pinkham - Author
#!/bin/bash

valgrind="valgrind --leak-check=full --show-leak-kinds=all ./server "
outspace="echo -e '\n\n\n'"
memchk="eval "$outspace";"$valgrind

# Try no arguments
$memchk 

# Invalid trust mode
$memchk 12344 ur key_cli.pub.pem key_serv.pem
$memchk 12344 tr key_cli.pub.pem key_serv.pem

# Invalid file names 
$memchk 12344 ur key_cli.pub.pe key_serv.pem
$memchk 12344 tr key_cli.pub.pem key_serv.pe

# Invalid port number 
$memchk 77777 t key_cli.pub.pem key_serv.pem

# Valid input 1
$memchk 12344 t key_cli.pub.pem key_serv.pem

# Valid input 2
$memchk 12344 u key_cli.pub.pem key_serv.pem
