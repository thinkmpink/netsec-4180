Michael Pinkham - Author (mlp2185@columbia.edu)
COMS4180 Network Security
Programming Assignment 1

1 What to install (using `sudo apt-get install`)
 - gcc
 - make
 - valgrind
 - openssl
 - git (don't need this but it's what I installed)

2 Inputs and input validation

 - Client input (after `$ ./client`): `<Password> <Relative or full plaintext filepath> <Server IP address or name> <Server port number> <Client private RSA key file name> <Server public RSA key file name>`
 - Server input (after `$ ./server`): `<Server port number> <Trust mode [t/u]> <Client public RSA key file name> <Server private RSA key file name>`
 - The user may also generate any fakefile and use the provided shell scripts for testing. First run `$ ./testServer.sh` until it blocks waiting for the client, then run `$ ./testClient.sh` on a different connection to the same machine. If the connection is on different machines, make sure to put the correct RSA keys in the directory from which each executable is run. I.e. put the client's public key and the server's private keyin the directory from which the server will be run. Hopefully I didn't forget any invalid inputs/

3 RSA key generation

 - Enter the following to generate keys that will be accepted by the program (they only need to end with .pem for the private key or .pub.pem for the public key, they don't need to have the exact filenames I suggest).
 - Generate the client key: `$ openssl genrsa -out key_cli.pem 2048`
 - Put pubkey in a new file: `$ openssl rsa -in key_cli.pem -pubout -out key_cli.pub.pem`
 - Generate the client key: `$ openssl genrsa -out key_serv.pem 2048`
 - Put pubkey in a new file: `$ openssl rsa -in key_serv.pem -pubout -out key_serv.pub.pem`
