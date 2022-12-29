#include "../Headers/Errors.h"

void ErrorCheck (int RetCode, char * Message)
{
    if (RetCode != LDAP_SUCCESS)
    {
        printf("[-] %s: %s\n", Message, ldap_err2string(RetCode));
        exit(EXIT_FAILURE);
    }
}
