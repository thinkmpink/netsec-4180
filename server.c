/* Michael Pinkham - Author */

#include <arpa/inet.h>
#include <bsd/string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h> 
#include <sys/socket.h>
#include <unistd.h>             /* for close() */

#define ERRBUFSIZE 1024


void decryptAndVerify(FILE *encFileAll, char *result, const char *mode,
    const char *cPubKeyFilepath, const char *sPrivKeyFilepath);
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
    

    /* Incorrect number of args */
    if (argc != 5)
    {
        char *msgStart     = "Incorrect number of arguments.\nUsage: ";
        char *requiredArgs = " <Server Port> <Trust mode [t/u]>" 
                             " <Client Public RSA Key Filepath>"
                             " <Server Private RSA Key Filepath>\n";
        strlcpy(msgBuffer, msgStart, ERRBUFSIZE);
        strlcat(msgBuffer, argv[0], ERRBUFSIZE);
        strlcat(msgBuffer, requiredArgs, ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }

    char *serverPort            = argv[1];
    char *trustMode             = argv[2];
    char *cPubKeyFilepath       = argv[3];
    char *sPrivKeyFilepath      = argv[4];
    char *fileNameToDecrypt     = "serv_encrypted_all.bin";
    unsigned short sPort;

    /* Minimal checking on RSA keys. Will pass this test if file
     * opens and the name has a valid format. */
    FILE *sPrivKeyF = fopen(sPrivKeyFilepath, "rb");
    if (!sPrivKeyF || sPrivKeyFilepath[strlen(sPrivKeyFilepath)-1] == '/')
    {
        if (sPrivKeyF) fclose(sPrivKeyF);
        strlcpy(msgBuffer, "File '", ERRBUFSIZE);
        strlcat(msgBuffer, sPrivKeyFilepath, ERRBUFSIZE);
        strlcat(msgBuffer, "' does not exist.\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }
    fclose(sPrivKeyF);

    FILE *cPubKeyF = fopen(cPubKeyFilepath, "rb");
    if (!cPubKeyF || cPubKeyFilepath[strlen(cPubKeyFilepath)-1] == '/')
    {
        if (cPubKeyF) fclose(cPubKeyF);
        strlcpy(msgBuffer, "File '", ERRBUFSIZE);
        strlcat(msgBuffer, cPubKeyFilepath, ERRBUFSIZE);
        strlcat(msgBuffer, "' does not exist.\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }
    fclose(cPubKeyF);
    

    
    /* Parse trust mode */
    if ((strncmp(trustMode, "t", 2)) && (strncmp(trustMode, "u", 2)))
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
    if (!(encDataFile = fopen("serv_encrypted_all.bin", "w+")))
    {
        close(welcomeSock);
        close(clientSock);
        freeaddrinfo(res);
        errorExitWithMessage("(server) fopen() failed\n");
    }

    /* Server receives encrypted bytes from client
     * Server writes the bytes to 'encryptedfile', a temp file 
     */
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
        errorExitWithMessage("fopen() failed to open"
            "serv_encrypted_all.bin\n");
    }

    /* Server will write result of verification here */
    char verificationResult[20];
    memset(verificationResult, 0, 20);
    decryptAndVerify(fileToDecrypt, (char *) verificationResult,
              trustMode, cPubKeyFilepath, sPrivKeyFilepath);
    
    fprintf(stdout, "%s\n", verificationResult);

    fclose(fileToDecrypt); //TODO: delete it?
    exit(0);
}



/* encFileAll: the open fakefile or serv_encrypted_all.bin
 * result: the buffer in the calling function to which to write
 *         either 'Verification Failed' or 'Verification Passed' 
 */
void decryptAndVerify(FILE *encFileAll, char *result, const char *mode,
    const char *cPubKeyFilepath, const char *sPrivKeyFilepath)
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
    if(fseek(encFileAll, 0, SEEK_END))
    {
        fclose(encFileAll);
        errorExitWithMessage("fseek( ..., SEEK_END) failed\n");
    }

    /* Save length of file */
    if((fSize = ftell(encFileAll)) < 0)
    {
        fclose(encFileAll);
        errorExitWithMessage("ftell() failed\n");
    }

    /* Move cursor back to beginning of file */
    if(fseek(encFileAll, 0, SEEK_SET))
    {
        fclose(encFileAll);
        errorExitWithMessage("fseek( ..., SEEK_SET) failed\n");
    }

    /* Allocate enough memory for file */
    if(!(fBuf = malloc(fSize)))
    {
        fclose(encFileAll);
        errorExitWithMessage("malloc() failed to allocate size of file\n");
    }
    
    /* Read the file into memory */
    if (fSize != (fread(fBuf, 1, fSize, encFileAll)))
    {
        fclose(encFileAll);
        free(fBuf);
        errorExitWithMessage("fread() failed. file length too short\n");
    }

    /* Find all tags */
    int i;
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
        fprintf(stderr, "Verification failed in 15 dig num bytes.\n");
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
        fprintf(stderr, "Verification failed in invalid byte len.\n");
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
        fprintf(stderr, "Verification failed in convert str byte.\n");
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
        fprintf(stderr, "Verification failed in Verif spec num byte.\n");
        strncpy(result, "Verification Failed", 20);
        return;
    }

    /* Write the three encrypted pieces to separate files */
    FILE *passF = fopen("serv_enc_password.bin", "wb");
    if (!passF)
    {
        free(fBuf);
        errorExitWithMessage("fopen() serv_enc_password.bin failed \n");
    }
    if (pLen != fwrite(pData, 1, pLen, passF))
    {
        free(fBuf);
        errorExitWithMessage("fwrite() serv_enc_password.bin failed \n");
    }
    if (fclose(passF))
    {
        free(fBuf);
        errorExitWithMessage("fclose() failed \n");
    }

    FILE *encF = fopen("serv_enc_data.bin", "wb");
    if (!encF)
    {
        free(fBuf);
        errorExitWithMessage("fopen() serv_enc_data.bin failed \n");
    }
    if (eLen != fwrite(eData, 1, eLen, encF))
    {
        free(fBuf);
        errorExitWithMessage("fwrite() serv_enc_data.bin failed \n");
    }
    if (fclose(encF))
    {
        free(fBuf);
        errorExitWithMessage("fclose() failed \n");
    }

    FILE *sigF = fopen("serv_enc_cli_sig.bin", "wb");
    if (!sigF)
    {
        free(fBuf);
        errorExitWithMessage("fopen() serv_enc_cli_sig.bin failed \n");
    }
    if (sLen != fwrite(sData, 1, sLen, sigF))
    {
        free(fBuf);
        errorExitWithMessage("fwrite() serv_enc_cli_sig.bin failed \n");
    }
    if (fclose(sigF))
    {
        free(fBuf);
        errorExitWithMessage("fclose() failed \n");
    }


    /* Decrypt the password using server privkey, save to file, then to
     * char buf in parent (will need to sleep() again) */
    pid_t passPID, encPID, sigPID;

    passPID = fork();
    if (passPID < 0)
    {
        free(fBuf);
        errorExitWithMessage("fork() 1 (server) failed \n");
    }
    if (passPID == 0) // Child process, execute (Decrypt client password)
    {
        if (execlp("openssl", "rsautl", "-decrypt", "-inkey",
                   sPrivKeyFilepath, "-in", 
                   "serv_enc_password.bin", "-out", 
                   "serv_dec_password.bin", (char *) NULL) < 0)
        {
            free(fBuf);
            strncpy(result, "Verification Failed", 20);
            fprintf(stderr, "Failed in child 1.\n");
            return;
        }
    }

    sleep(1); /* We need the child to write the password file before
               * proceeding. Now get password and delete PT password */
    FILE *dPass = fopen("serv_dec_password.bin", "rb");
    if (!dPass)
    {
        free(fBuf);
        errorExitWithMessage("fopen() (serv_dec_password.bin failed \n");
    }
    char pass[17];
    if (16 != fread((char *)pass, 1, 16, dPass))
    {
        free(fBuf);
        fclose(dPass);
        strncpy(result, "Verification Failed", 20);
        return;
    }
    pass[16] = 0;

    if (fclose(dPass))
    {
        free(fBuf);
        errorExitWithMessage("fclose() PT passfile failed\n");
    }




    /* Choose what to decrypt based on trust mode */
    char *eDataFilename = "serv_enc_data.bin";
    if (mode[0] == 'u')
    {
        eDataFilename = "fakefile";
    }


    
    encPID = fork(); /* Fork again */
    if (encPID < 0)
    {
        free(fBuf);
        errorExitWithMessage("fork() 2 (server) failed \n");
    }

    if (encPID == 0) // Child 2. Execute. (Decrypt client CT)
    {
        if (execlp("openssl", "enc", "-d", "-aes-128-cbc", "-in",
                   eDataFilename, "-out", "decryptedfile", 
                   "-pass", 
                   "file:serv_dec_password.bin", (char *) NULL) < 0)
        {
            free(fBuf);
            fprintf(stderr, "Failed in child 2.\n");
            strncpy(result, "Verification Failed", 20);
            return;
        }
    }
    
    /* (Back in parent) Remove the PT password asap */
    sleep(1);
    if (remove("serv_dec_password.bin"))
    {
        free(fBuf);
        errorExitWithMessage("remove() PT passfile failed\n");
    }
    
    /* Fork a final time to complete verification */
    sigPID = fork(); 
    if (sigPID < 0)
    {
        free(fBuf);
        errorExitWithMessage("fork() 3 (server) failed \n");
    }

    if (sigPID == 0) /* Child 3. Execute. (verify client signature) */
    {
        if (execlp("openssl", "dgst", "-sha256", "-out", 
                   "verification_result", "-verify",
                   cPubKeyFilepath, "-signature",
                   "serv_enc_cli_sig.bin", "decryptedfile",
                   (char *) NULL) < 0)
        {
            free(fBuf);
            fprintf(stderr, "Failed in child 3.\n");
            strncpy(result, "Verification Failed", 20);
            return;
        }
    }

    sleep(1);
    /* Open verification result and see what's inside */
    FILE *resultF = fopen("verification_result", "rb");
    if (!resultF)
    {
        free(fBuf);
        fprintf(stderr, "fopen() failed on verification_result\n");
        strncpy(result, "Verification Failed", 20);
        return;
    }
    char vResult[30];
    memset((char *) vResult, 0, 30);
    if (10 > fread((char *) vResult, 1, 25, resultF))
    {  /* Output should have been "Verified OK" or "Verification Failure" */
        free(fBuf);
        fprintf(stderr, "fread() failed on verification_result\n");
        strncpy(result, "Verification Failed", 20);
        return;
    }
    if (fclose(resultF))
    {
        free(fBuf);
        fprintf(stderr, "fclose() failed on verification_result\n");
        strncpy(result, "Verification Failed", 20);
        return;
    }


    if (!strncmp(vResult, "Verification Failure", 20))
    {
        free(fBuf);
        fprintf(stderr, "verification_result was negative\n");
        strncpy(result, "Verification Failed", 20);
        return;
    }

    free(fBuf);
    strncpy(result, "Verification Passed", 20);
    return;
}


