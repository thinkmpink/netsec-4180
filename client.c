#include <stdio.h>
#include <stdlib.h> 
#include <bsd/string.h>

#define ERRBUFSIZE 1024

int errorExitWithMessage(const char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(1);
}


/* Input error suite */
void checkInputErrors(int argc, char **argv)
{
    
    char msgBuffer[ERRBUFSIZE];
    
    //TODO: get rid of this once done with error checking

    fprintf(stderr, "%d args\n", argc);

    /* Incorrect number of args */
    if (argc != 6)
    {
        //TODO: fix <RSA components opts
        char *msgStart     = "Incorrect number of arguments.\nUsage: ";
        char *requiredArgs = " <Password> <Full file path> <Server IP or Name>" 
                             " <Server Port> <RSA components>\n";
        strlcpy(msgBuffer, msgStart, ERRBUFSIZE);
        strlcat(msgBuffer, argv[0], ERRBUFSIZE);
        strlcat(msgBuffer, requiredArgs, ERRBUFSIZE);
        
        errorExitWithMessage(msgBuffer);
    }

    /* Incorrect password */
    if (strlen(argv[1]) != 16) //||is
    {
        char *msg = "Password must be exactly 16 characters long.";
	errorExitWithMessage(msg);
    }
    
}

int main(int argc, char **argv)
{
    checkInputErrors(argc, argv);

    exit(0);
}

