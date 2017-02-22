
#include <arpa/inet.h>
#include <bsd/string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h> 
#include <sys/socket.h>
#include <unistd.h>             /* for close() */

#define ERRBUFSIZE 1024


//TODO: move this to a header file
void decryptAndVerify(FILE *encFile, char *result);
int errorExitWithMessage(const char *msg);
int isAlphaNum(const char *str);
unsigned short getPort(const char *c);



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
    char *fileNameToDecrypt     = "encryptedfile";
    unsigned short sPort;

    //TODO: add section to check RSA info
    
    /* Parse trust mode */
    if (!(strncmp(trustMode, "t", 2)))
    {
        ; //Do nothing
    }
    else if (!(strncmp(trustMode, "u", 2)))
    {
        fileNameToDecrypt = "fakefile";
    }
    else
    {
        errorExitWithMessage("Unrecognized trust mode. Rerun with [t/u]\n");
    }


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
        perror("(server) bind() failed, closing socket\n");
    }

    /* Could not bind to socket */
    if (!res) 
    {
        close(welcomeSock);
        freeaddrinfo(res);
        errorExitWithMessage("(server) bound to invalid port.\n");
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
    struct sockaddr_storage clientAddr; 
    socklen_t addr_size = sizeof(clientAddr);
    if ((clientSock = accept(welcomeSock, 
                            (struct sockaddr *) &clientAddr, 
                            &addr_size)) <= 0)
    {
        close(clientSock);
        freeaddrinfo(res);
        errorExitWithMessage("(server) accept() failed.\n");
    }


    /* Receive encrypted bytes */
    char encDataBuf[ERRBUFSIZE];
    int readCount;
    int writeCount;
    FILE *encDataFile;

    /* Open intermediate file to write received bytes to. */
    //TODO: possible data race with fileToDecrypt pointer
    if (!(encDataFile = fopen("encryptedfile", "w+")))
    {
        close(welcomeSock);
        close(clientSock);
        freeaddrinfo(res);
        errorExitWithMessage("(server) fopen() failed\n");
    }

    /* Server receives encrypted bytes from client
     * Server writes the bytes to 'encryptedfile', a temp file 
     */
     //TODO: delete the temp file?
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
            errorExitWithMessage("(server) fwrite() failed\n");
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

    /* 
     * Close the file of bytes the client sent, and open the file 
     * determined by the trust mode (which is the same or 'fakefile'). 
     * Halt and clean up if we cannot open this file. In all cases, 
     * close the connection to the client and the server socket.
     */
    fclose(encDataFile);
    close(welcomeSock);
    close(clientSock);
    freeaddrinfo(res);

    FILE *fileToDecrypt;
    if (!(fileToDecrypt = fopen(fileNameToDecrypt, "rb")))
    {
        errorExitWithMessage("fopen() failed to open encryptedfile/fakefile\n");
    }

    /* Server will write result of verification here */
    char verificationResult[20];
    memset(verificationResult, 0, 20);
    decryptAndVerify(fileToDecrypt, (char *) verificationResult);
    
    fprintf(stdout, "%s\n", verificationResult);

    fclose(fileToDecrypt); //TODO: delete it?
    exit(0);
}



//TODO: decrypt file using libcrypto 
//TODO: verify signature, output Verification result

void decryptAndVerify(FILE *encFile, char *result)
{
    /*
     * Tags will specify the arrangement of data in fileToDecrypt.
     * A tag can be one of the following, where N is the number of bytes:
     *
     *   EncryptedFile[N] 
     *   Password[N]
     *   Signature[N]
     *
     * The sender must send all of these tags with no space before the
     * encrypted data, for the data to be properly decrypted. The tags
     * must not be encrypted, and must be fully in ASCII byte format. In 
     * particular, N must be a decimal-formatted string (terminated by 
     * the closing bracket). The order of the three is up to the client.
     */

    /* [Verification Step 1] Verify and find tags */
    char *encData, *encPassword, *signature; //Pointers to the tags
    char *eData, *pData, *sData; //Pointers to the data after the tags
    encData = NULL; eData = encData;
    encPassword = NULL; pData = encPassword;
    signature = NULL; sData = signature;
    long fSize;
    char *fBuf;

    /* Position stream at end of file to get num bytes*/
    if(fseek(encFile, 0, SEEK_END))
    {
        fclose(encFile);
        errorExitWithMessage("fseek( ..., SEEK_END) failed\n");
    }

    /* Save length of file */
    if((fSize = ftell(encFile)) < 0)
    {
        fclose(encFile);
        errorExitWithMessage("ftell() failed\n");
    }

    /* Move cursor back to beginning of file */
    if(fseek(encFile, 0, SEEK_SET))
    {
        fclose(encFile);
        errorExitWithMessage("fseek( ..., SEEK_SET) failed\n");
    }

    /* Allocate enough memory for file */
    if(!(fBuf = malloc(fSize)))
    {
        fclose(encFile);
        errorExitWithMessage("malloc() failed to allocate size of file\n");
    }
    
    /* Read the file into memory */
    int i;
    for (i = 0; i < fSize; i++)
    {
        if ((fBuf[i] = fgetc(encFile)) < 0)
        {
            fclose(encFile);
            free(fBuf);
            errorExitWithMessage("fgetc() failed. file length too short\n");
        }
    } 

    /* Find all tags */
    char c;
    for (i = 0; i < fSize; i++)
    {
        c = fBuf[i];

        if (c == 'E')
        {
            /* Test for EncryptedFile tag */
            if(!(strncmp(fBuf + i, "EncryptedFile[", 14)))
            {
                encData = fBuf + i;        
            }
        }

        else if (c == 'P')
        {
            /* Test for Password tag */
            if(!(strncmp(fBuf + i, "Password[", 9)))
            {
                encPassword = fBuf + i;        
            }
        }

        else if (c == 'S')
        {
            /* Test for Signature tag */
            if(!(strncmp(fBuf + i, "Signature[", 10)))
            {
                signature = fBuf + i;        
            }
        }
    }

    /* Output 'Verification Failed' if we are missing a piece */
    if (!encData || !encPassword || !signature) 
    {
        free(fBuf);
        strncpy(result, "Verification Failed", 20);
        return;
    }
    
    /* Validate byte lengths */
    encData += 14;
    encPassword += 9;
    signature += 10;
    
    /* Allow up to 15 digits for number of bytes */
    char encDataLenStr[16], encPasswordLenStr[16], signatureLenStr[16];
    memset(encDataLenStr, 0, 16);
    memset(encPasswordLenStr, 0, 16);
    memset(signatureLenStr, 0, 16);
    char cE, cP, cS;
    if (!(encData + 15 < fBuf + fSize 
     && encPassword + 15 < fBuf + fSize
     && signature + 15 < fBuf + fSize))
    {
        free(fBuf);
        strncpy(result, "Verification Failed", 20);
        return;
    }

    /* Copy length strings to buffers, null-terminate them */
    unsigned char lenStrComplete = 0;
    for (i = 0; i < 15; i++)
    {
        cE = encData[i]; 
        cP = encPassword[i];
        cS = signature[i];
        if (cE == ']')
        {
            encDataLenStr[i] = 0;
            eData = encData + i + 1;
            lenStrComplete += 1;
        }
        
        else 
        {
            encDataLenStr[i] = cE;
        }

        if (cP == ']')
        {
            encPasswordLenStr[i] = 0;
            pData = encPassword + i + 1;
            lenStrComplete += 1;
        }

        else 
        {
            encPasswordLenStr[i] = cP;
        }

        if (cS == ']')
        {
            signatureLenStr[i] = 0;
            sData = signature + i + 1;
            lenStrComplete += 1;
        }

        else 
        {
            signatureLenStr[i] = cS;
        }
    }

    /* Invalid byte length */
    if (lenStrComplete != 3)
    {
        free(fBuf);
        strncpy(result, "Verification Failed", 20);
        return;
    }

    /* Convert string byte lengths to longs */
    long encDataLen, encPasswordLen, signatureLen;
    if ((encDataLen = strtol(encDataLenStr, NULL, 10)) < 1
     || (encPasswordLen = strtol(encPasswordLenStr, NULL, 10)) < 1
     || (signatureLen = strtol(signatureLenStr, NULL, 10)) < 1
     )
    {
        free(fBuf);
        strncpy(result, "Verification Failed", 20);
        return;
    }

    /* Verify that there are the specified number of bytes in each section */  
    int eLen = (int) encDataLen;
    int pLen = (int) encPasswordLen;
    int sLen = (int) signatureLen;
    if (eData + eLen > fBuf + fSize
     || sData + sLen > fBuf + fSize
     || pData + pLen > fBuf + fSize
    )
    {
        free(fBuf);
        strncpy(result, "Verification Failed", 20);
        return;
    }

    
    strncpy(result, "Verification Passed", 20);
    return;
}


