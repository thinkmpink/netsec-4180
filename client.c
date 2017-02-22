/* Michael Pinkham - Author */

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
    FILE *f, *cPrivKeyF, *sPubKeyF;
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

    /* Minimal checking on RSA keys. Will pass this test if file
     * opens and the name has a valid format. */
    cPrivKeyF = fopen(cPrivKeyFilepath, "rb");
    if (!cPrivKeyF || cPrivKeyFilepath[strlen(cPrivKeyFilepath)-1] == '/')
    {
        if (cPrivKeyF) fclose(cPrivKeyF);
        strlcpy(msgBuffer, "File '", ERRBUFSIZE);
        strlcat(msgBuffer, cPrivKeyFilepath, ERRBUFSIZE);
        strlcat(msgBuffer, "' does not exist.\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }
    fclose(cPrivKeyF);

    sPubKeyF = fopen(sPubKeyFilepath, "rb");
    if (!sPubKeyF || sPubKeyFilepath[strlen(sPubKeyFilepath)-1] == '/')
    {
        if (sPubKeyF) fclose(sPubKeyF);
        strlcpy(msgBuffer, "File '", ERRBUFSIZE);
        strlcat(msgBuffer, sPubKeyFilepath, ERRBUFSIZE);
        strlcat(msgBuffer, "' does not exist.\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }
    fclose(sPubKeyF);

    /* Incorrect server port number */
    if (!(sPort = getPort(serverPort)))
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
  /*  while ((readCount = fread(encDataBuf, 1, 1024, f)))
    {
        if (send(sockfd, encDataBuf, readCount, 0) == -1)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Connected, but send() failed.\n");
        }
    }
  */
    /* Since we are using exec() to do the crypto, which won't return, 
     * we need to create forks to call exec */

    pid_t fileEncPID, sigPID, passPID;
    fileEncPID = fork();
    
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

    passPID = fork();
    if (passPID < 0)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fork() 3 failed.\n");
    }

    if (passPID == 0) // Child process 3, execute
    {
        /* Encrypt the AES password using the server's public RSA key.
         */ 
        FILE *passFile = fopen("passfile", "wb");
        if (!passFile)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Password temp write failed (this is a hack).\n");
        }
        fwrite(password, 1, 16, passFile);
        fclose(passFile);
        if(execlp("openssl", "rsautl", "-encrypt", "-inkey", sPubKeyFilepath,
                  "-pubin", "-in", "passfile", "-out", 
                  "./password.enc", (char *) NULL) < 0)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            if (remove("passfile")) 
            {
                errorExitWithMessage("remove() failed.\n");
            }
            errorExitWithMessage("Encrypting password failed.\n");
        }
        // Should not get here
    }

    /* We're in the parent process. Wait a little, then open the files and 
     * send the data to the server */
    sleep(1);

    /* First clean up the hack */
    if (remove("passfile")) 
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("remove() failed.\n");
    }
    
    /* Open the encrypted data files */
    FILE *eData = fopen("encfile.enc", "rb");
    if (!eData) 
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Client: fopen() CT failed.\n");
    }
    FILE *sData = fopen("clientsig.sign", "rb");
    if (!sData) 
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Client: fopen() signature failed.\n");
    }
    FILE *pData = fopen("password.enc", "rb");
    if (!pData) 
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Client: fopen() encrypted password failed.\n");
    }

    /* Get number of bytes of each data piece */
    int eSize;
    if (fseek(eData, 0, SEEK_END))
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fseek() failed\n");
    }
    
    if ((eSize = ftell(eData)) < 0)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("ftell() failed\n");
    }

    if (fseek(eData, 0, SEEK_SET))
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fseek() failed\n");
    }

    int sSize;
    if (fseek(sData, 0, SEEK_END))
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fseek() failed\n");
    }
    
    if ((sSize = ftell(sData)) < 0)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("ftell() failed\n");
    }

    if (fseek(sData, 0, SEEK_SET))
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fseek() failed\n");
    }

    int pSize;
    if (fseek(pData, 0, SEEK_END))
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fseek() failed\n");
    }
    
    if ((pSize = ftell(pData)) < 0)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("ftell() failed\n");
    }

    if (fseek(pData, 0, SEEK_SET))
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("fseek() failed\n");
    }

    /* Write the tags */
    char eTag[40], sTag[40], pTag[40];
    snprintf(eTag, 40, "EncryptedFile[%d]", eSize);
    snprintf(pTag, 40, "Password[%d]", pSize);
    snprintf(sTag, 40, "Signature[%d]", sSize);

    /* Send() the data to the server */
    if (send(sockfd, eTag, strlen(eTag), 0) == -1)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Connected, but send() failed on eTag.\n");
    }
    while ((readCount = fread(encDataBuf, 1, 1024, eData)))
    {
        if (send(sockfd, encDataBuf, readCount, 0) == -1)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Connected, but send() failed on eData.\n");
        }
    }

    if (send(sockfd, sTag, strlen(sTag), 0) == -1)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Connected, but send() failed on sTag.\n");
    }
    while ((readCount = fread(encDataBuf, 1, 1024, sData)))
    {
        if (send(sockfd, encDataBuf, readCount, 0) == -1)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Connected, but send() failed on sData.\n");
        }
    }
     
    if (send(sockfd, pTag, strlen(pTag), 0) == -1)
    {
        fclose(f);
        freeaddrinfo(servinfo);
        errorExitWithMessage("Connected, but send() failed on pTag.\n");
    }
    while ((readCount = fread(encDataBuf, 1, 1024, pData)))
    {
        if (send(sockfd, encDataBuf, readCount, 0) == -1)
        {
            fclose(f);
            freeaddrinfo(servinfo);
            errorExitWithMessage("Connected, but send() failed on pData.\n");
        }
    }  
    

    fclose(eData);
    fclose(sData);
    fclose(pData);

    fclose(f);
    freeaddrinfo(servinfo);
    exit(0);
}

