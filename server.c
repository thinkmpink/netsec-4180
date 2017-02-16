
#include <arpa/inet.h>
#include <bsd/string.h>
//#include <libexplain/listen.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h> 
#include <sys/socket.h>
#include <sys/types.h>  //TODO: do we need this
#include <unistd.h>             /* for close() */

#define ERRBUFSIZE 1024

/* Terminates execution of the program and prints the error message argument */
int errorExitWithMessage(const char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(1);
}

/* Returns 1 if str contains only characters in 0-9A-Za-z, 0 otherwise */
int isAlphaNum(const char *str)
{
    char c;
    const char *s = str;
    while ((c = *s++) != 0)
    {
        if (!(
              (c > 47 && c < 58) 
           || (c > 64 && c < 91)
           || (c > 96 && c < 123)
	)) return 0;
    }
    return 1;
}


/* Return port number if the port number n is 0 < n 65536, else 0 */
unsigned short getPort(const char *c)
{   
    long numDec = strtol(c, NULL, 10);
    long numHex = strtol(c, NULL, 16);
    if (numDec > 0 && numDec < 65536) return (unsigned short) numDec; 
    else if (numHex > 0 && numHex < 65536) return (unsigned short) numHex;
    else return 0;
}

int main(int argc, char **argv)
{
    
    /*
     * Input error suite 
     *
     *
     */
    char msgBuffer[ERRBUFSIZE];
    
    //TODO: get rid of this once done with error checking

    fprintf(stderr, "%d args\n", argc);

    /* Incorrect number of args */
    if (argc != 4)
    {
        //TODO: fix <RSA components opts
        char *msgStart     = "Incorrect number of arguments.\nUsage: ";
        char *requiredArgs = " <Server Port> <Trust mode [t/u]>" 
                             " <RSA components>\n";
        strlcpy(msgBuffer, msgStart, ERRBUFSIZE);
        strlcat(msgBuffer, argv[0], ERRBUFSIZE);
        strlcat(msgBuffer, requiredArgs, ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }

    char *serverPort            = argv[1];
    char *trustMode             = argv[2];
    char *rsaPrivKeyFilepath    = argv[3];
    unsigned short sPort;
    //TODO: do we need this?: struct hostent host;



    //TODO: add section to check RSA info

    /* Incorrect server port number */
    if (!(sPort = getPort(serverPort)))
        errorExitWithMessage("Please enter a port number 0 < n < 65536. \n");
    
    /* Convert server port back to decimal string */
    char servPortDecStr[6];
    memset(servPortDecStr, 0, 6);
    snprintf(servPortDecStr, 5, "%d", sPort);

    /* Test that server address is valid, save address info in res */
    int welcomeSock;
    struct addrinfo hints, *res;
    int errnum;
    memset(&hints, 0, sizeof hints);
    hints.ai_family     = AF_UNSPEC;
    hints.ai_socktype   = SOCK_STREAM;
    hints.ai_flags      = AI_PASSIVE;

    if ((errnum = getaddrinfo(NULL, servPortDecStr, &hints, &res)) != 0)
    {
        strlcpy(msgBuffer, "getaddrinfo() failed: ", ERRBUFSIZE);
        strlcat(msgBuffer, gai_strerror(errnum), ERRBUFSIZE);
        strlcat(msgBuffer, "\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }

    
    /*
     * End of error suite.
     *
     * Set up socket.
     */
    
    /* Try to make socket and bind to it */
    if ((welcomeSock = socket(res->ai_family, res->ai_socktype, 
                         res->ai_protocol)) == -1)
    {
        perror("socket() failed\n");
    }    

    if (bind(welcomeSock, res->ai_addr, res->ai_addrlen) == -1)
    {
        close(welcomeSock);
        perror("(server) connect() failed, closing socket\n");
    }

    /* Could not bind to socket */
    if (!res) 
    {
        close(welcomeSock);
        freeaddrinfo(res);
        errorExitWithMessage("(server) failed to bind to socket.\n");
    }

    /* Now wait for incoming connections. */
    int maxConn = 5;
    int listenOut;
    if ((listenOut = listen(welcomeSock, maxConn)) < 0)
    {
        close(welcomeSock);
        fprintf(stderr, "%s\n", strerror(listenOut));
        freeaddrinfo(res);
        errorExitWithMessage("(server) listen() failed.\n");
    }

    /* Now accept the incoming connection and create a new socket for it. */
    int clientSock;
    struct sockaddr_storage clientAddr; //TODO: try sockaddr_storage
    socklen_t addr_size = sizeof(clientAddr);
    if ((clientSock = accept(welcomeSock, 
                            (struct sockaddr *) &clientAddr, 
                            &addr_size)) <= 0)
    {
        //close(welcomeSock);
        close(clientSock);
        freeaddrinfo(res);
        errorExitWithMessage("accept() failed.\n");
    }


    /* Receive encrypted bytes */
    char encDataBuf[ERRBUFSIZE];
    int readCount;
    int writeCount;
    FILE *encDataFile;

    /* Open intermediate file to write received bytes to. */
    if (!(encDataFile = fopen("encryptedfile", "w+")))
    {
        close(welcomeSock);
        close(clientSock);
        freeaddrinfo(res);
        errorExitWithMessage("fopen() failed\n");
    }

    while ((readCount = recv(clientSock, encDataBuf, ERRBUFSIZE, 0)) > 0)
    {
        /* Write bytes to disk, or exit while loop if read 0 bytes */
        if ((writeCount = fwrite(encDataBuf, 1, readCount, encDataFile)) 
            != readCount)
        {
            close(welcomeSock);
            close(clientSock);
            fclose(encDataFile);
            freeaddrinfo(res);
            errorExitWithMessage("fwrite() failed\n");
        }
        //TODO: maybe need other error checking on writeCount?
    }

    /* Recv error */
    if (readCount < 0)
    {   
        close(welcomeSock);
        close(clientSock);
        fclose(encDataFile);
        freeaddrinfo(res);
        errorExitWithMessage("recv() failed\n");
    }


    //TODO: decrypt file using execl with opts from cookbook
    //TODO: verify signature, output Verification result


    close(welcomeSock);
    close(clientSock);
    fclose(encDataFile);
    freeaddrinfo(res);
    exit(0);
}

