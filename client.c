#include <stdio.h>
#include <stdlib.h> 
#include <bsd/string.h>
#include <arpa/inet.h>
#include <netdb.h>

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

/* Return 1 if filepath can be opened and does not end with '/', else 0 */
int isValidFilepath(const char *filepath)
{
    FILE *f = fopen(filepath, "r");
    if (!f || filepath[strlen(filepath)-1] == '/')
    {
       fclose(f);
       return 0;
    }
    else
    {  
       fclose(f);
       return 1;
    }
}

/* Return 1 if server is a valid dotted quad or can be found in a DNS
 * lookup. 0 otherwise. */
int isValidServerName(const char *server)
{
    //struct hostent *he;    /* Server IP struct */
    struct in_addr addr4;  /* Server address IPv4 */
    struct in6_addr addr6; /* Server address IPv4 */
    if (inet_pton(AF_INET, server, &addr4) 
     || inet_pton(AF_INET6, server, &addr6)
     || gethostbyname(server)
    ) return 1;
    else return 0;
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

    char *password = argv[1];
    char *filepath = argv[2];
    char *serverIP = argv[3];
    char *serverPort = argv[4];
    char *rsaComponents  = argv[5];

    /* Incorrect password */
    if (strlen(password) != 16) 
	errorExitWithMessage("Password must be exactly 16 characters long.\n");

    else if (!isAlphaNum(password)) 
        errorExitWithMessage("Password must only use letters A-Za-z and digits 0-9.\n");

    /* Incorrect filepath */
    else if (!isValidFilepath(filepath))
    {
        strlcpy(msgBuffer, "File '", ERRBUFSIZE);
        strlcat(msgBuffer, filepath, ERRBUFSIZE);
        strlcat(msgBuffer, "' does not exist.\n", ERRBUFSIZE);
        errorExitWithMessage(msgBuffer);
    }
    
    else if (!isValidServerName(serverIP))
        errorExitWithMessage("Please enter a valid dotted quad or server name.\n");

}

int main(int argc, char **argv)
{
    /* Check all input except server validity. */
    checkInputErrors(argc, argv);

    exit(0);
}

