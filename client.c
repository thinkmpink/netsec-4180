
#include <arpa/inet.h>
#include <bsd/string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h> 
#include <sys/socket.h>
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
    if (argc != 7)
    {
        char *msgStart     = "Incorrect number of arguments.\nUsage: ";
        char *requiredArgs = " <Password> <Full file path> <Server IP or Name>" 
                             " <Server Port> <Client private key file name>"
                             " <Server public key file name>\n";
        strlcpy(msgBuffer, msgStart, ERRBUFSIZE);
        strlcat(msgBuffer, argv[0], ERRBUFSIZE);
        strlcat(msgBuffer, requiredArgs, ERRBUFSIZE);
        
        errorExitWithMessage(msgBuffer);
    }

    char *password              = argv[1];
    char *filepath              = argv[2];
    char *serverIP              = argv[3];
    char *serverPort            = argv[4];
    char *cPrivKeyFilepath      = argv[5];
    char *sPubKeyFilepath       = argv[6];
    FILE *f;
    unsigned short sPort;


    /* Incorrect password */
    if (strlen(password) != 16) 
	errorExitWithMessage("Password must be exactly 16 characters long.\n");

    else if (!isAlphaNum(password)) 
        errorExitWithMessage("Password must only use letters A-Za-z and digits 0-9.\n");

    /* Incorrect filepath */
    f = fopen(filepath, "rb");
    if (!f || filepath[strlen(filepath)-1] == '/')
    {
        if (f) fclose(f);
        strlcpy(msgBuffer, "File '", ERRBUFSIZE);
        strlcat(msgBuffer, filepath, ERRBUFSIZE);
        strlcat(msgBuffer, "' does not exist.\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }

    //TODO: add section to check RSA info

    /* Incorrect server port number */
    else if (!(sPort = getPort(serverPort)))
    {    
        fclose(f);
        errorExitWithMessage("Please enter a port number 0 < n < 65536. \n");
    }

    /* Convert server port back to decimal string */
    char servPortDecStr[6];
    snprintf(servPortDecStr, 5, "%d", sPort);

    /* Test that server address is valid, save address info in servinfo */
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int errno;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((errno = getaddrinfo(serverIP, servPortDecStr, &hints, &servinfo)) != 0)
    {
        strlcpy(msgBuffer, "Invalid name or address: ", ERRBUFSIZE);
        strlcat(msgBuffer, gai_strerror(errno), ERRBUFSIZE);
        strlcat(msgBuffer, "\n", ERRBUFSIZE);
        fclose(f);
        errorExitWithMessage(msgBuffer);
    }

    
    /*
     * End of error suite.
     *
     * Set up socket.
     */
    
    /* Test all possible connections in servinfo */
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, 
        p->ai_protocol)) == -1)
        {
            perror("socket() failed, testing next address\n");
            continue;
        }    

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            perror("connect() failed, closing socket\n");
            close(sockfd);
            continue;
        }

        break; /* This means we connected successfully */

    }
 
    /* Could not find any valid connection */
    if (!p) 
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Failed to connect to server.\n");
    }


    //In the meantime, just send a file in the clear. Ensure its transmission is
    //safe.
    char encDataBuf[ERRBUFSIZE];
    int readCount;
    while ((readCount = fread(encDataBuf, 1, 1024, f)))
    {
        if (send(sockfd, encDataBuf, readCount, 0) == -1)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Connected, but send() failed.\n");
        }
    }

    /* Since we are using exec() to do the crypto, which won't return, 
     * we need to create a fork to call exec */

    pid_t fileEncPID, sigPID, passPID;
    fileEncPID = fork();
    
    //v2
    if (fileEncPID < 0)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fork() 1 failed.\n");
    }

    if (fileEncPID == 0) // Child process, execute
    {
        // Encrypt the file using AES_128_CBC and the 16 byte key 
        if(execlp("openssl", "enc", "-e", "-aes-128-cbc", "-in", filepath, 
              "-out", "./encfile.enc",  "-k", password, (char *) NULL) < 0)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Encryption of PT failed.\n");
        }
        // Should not ever get here
    }   

    sigPID = fork();
    if (sigPID < 0)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fork() 2 failed.\n");
    }

    if (sigPID == 0) // Child process 2, execute
    {
        // Hash the file with SHA256 and sign it by encrypting the 
        // hash using the client's private RSA key. 
        if(execlp("openssl", "dgst", "-sha256", "-sign", 
                  cPrivKeyFilepath, "-out", "./clientsig.sign", 
                  filepath, (char *) NULL) < 0)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Signing PT failed.\n");
        }
        // Should not get here
    }

    /*
    if (fileEncPID >= 0) // Fork was successful
    {
        if (fileEncPID == 0) // Child process, execute
        {
            // Encrypt the file using AES_128_CBC and the 16 byte key 
            if(execlp("openssl", "enc", "-e", "-aes-128-cbc", "-in", filepath, 
                  "-out", "./encfile.enc",  "-k", password, (char *) NULL) < 0)
            {
                fclose(f);
                freeaddrinfo(servinfo);
                errorExitWithMessage("Encryption of PT failed.\n");
            }

            // Should not ever get here
        }

        else // Parent process
        {
            // Fork again to execute 
            sigPID = fork();
            if (sigPID >= 0) // Second fork successful
            {
                if (sigPID == 0) // Child process 2, execute
                {
                    // Hash the file with SHA256 and sign it by encrypting the 
                    // hash using the client's private RSA key. 
                    if(execlp("openssl", "dgst", "-sha256", "-sign", 
                              cPrivKeyFilepath, "-out", "./clientsig.sign", 
                              filepath, (char *) NULL) < 0)
                    {
                        fclose(f);
                        freeaddrinfo(servinfo);
                        errorExitWithMessage("Signing PT failed.\n");
                    }
                    // Should not get here
                }
                
                else // Parent process 2
                {
                    //TODO fork again and encrypt password
                    //TODO for now just clean up
                    fclose(f);
                    freeaddrinfo(servinfo);
                    exit(0);
                }

            }
        }
        
    } */





    /* Encrypt the AES password using the server's public RSA key.
     */
    //TODO


    fclose(f);
    freeaddrinfo(servinfo);
    exit(0);
}

