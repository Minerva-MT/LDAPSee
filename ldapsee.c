#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "Headers/LDAP.h"
#include "Headers/Modules.h"
#include "Headers/Errors.h"

char isVerbose  = 0;

void Usage(char * Name);

int main (int argc, char ** argv)
{
    LDAP    *        LDAPConnection;
        
    ////////////////////////////////////////////////////////////////////
    // User Supplied Options
    
    char *  URI         =   "";         // The LDAP URI
    
    char * Username     =   "";         // The Binding Username
    char * Password     =   "";         // The Binding Password
        
    char * BaseDN       =   "";         // The Base Distinguished Name
    
    ////////////////////////////////////////////////////////////////////
    
    int SizeLimit       =   1000;
    
    int LDAPVersion     =   3;
    
    int Option;
    
    char isAnonymous    =   0;
    
    while ((Option = getopt(argc, argv, "VU:S:B:")) != -1)
    {
        switch (Option)
        {
            case 'U':
                Username = optarg;
                break;
            case 'S':
                URI = optarg;
                break;
            case 'B':
                BaseDN = optarg;
                break;
            case 'V':
                isVerbose = 1;
                break;
        }
    }
    
    if (argc < 2 || URI[0] == 0)
        Usage(argv[0]);
        
    if (Username[0] == 0)
        isAnonymous = 1;
    else
        Password = getpass("Password: ");
        
    LDAP_Connect(&LDAPConnection, URI, LDAPVersion);

    int RetCode = isAnonymous ? LDAP_Bind(&LDAPConnection, "", "") : LDAP_Bind(&LDAPConnection, Username, Password); 
    
    ErrorCheck(RetCode, "Error Binding LDAP");
   
    if (!isAnonymous)
    {
        RetCode = ENUM_Context(&LDAPConnection); 
        ErrorCheck(RetCode, "Error Executing LDAP Query");
    }
    
    ENUM_Base(&LDAPConnection);
    ENUM_Users              (&LDAPConnection, BaseDN);
    ENUM_PasswordExpiry		(&LDAPConnection, BaseDN);
    ENUM_Computers          (&LDAPConnection, BaseDN);
    ENUM_Delegation         (&LDAPConnection, BaseDN);

    ENUM_GPO                (&LDAPConnection, BaseDN);
    ENUM_SPNs               (&LDAPConnection, BaseDN);
    ENUM_AdminCount         (&LDAPConnection, BaseDN);
    ENUM_PrivilegedUsers    (&LDAPConnection, BaseDN);
    ENUM_ASREP              (&LDAPConnection, BaseDN);
    
    Verbose("Closing LDAP Session\n");
    
    ldap_unbind_ext_s(LDAPConnection, NULL, NULL);
    
    
}

void Usage(char * Name)
{
    printf("  _        _____               _____     _____   ______   ______     \n");
    printf(" | |      |  __ \\      /\\     |  __ \\   / ____| |  ____| |  ____| \n");
    printf(" | |      | |  | |    /  \\    | |__) | | (___   | |__    | |__      \n");
    printf(" | |      | |  | |   / /\\ \\   |  ___/   \\___ \\  |  __|   |  __|  \n");
    printf(" | |____  | |__| |  / ____ \\  | |       ____) | | |____  | |____    \n");
    printf(" |______| |_____/  /_/    \\_\\ |_|      |_____/  |______| |______|  \n");
    printf("                                                                     \n");
    printf(" andrew.borg@minerva.com.mt                       by Minerva IS      \n");
    printf("\n                      Automated LDAP Enumerator                    \n");
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n");

    printf("Usage: \n");
    printf("     %s -S {LDAP URI} [-U {Username}] [-B {Base DN}]\n", Name);
    printf("          -S: LDAP URI\n");
    printf("          -B: LDAP Base Distinguished Name\n");
    printf("          -U: LDAP Binding Username (Password asked Interactively)\n");
    
    printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n");
    
    printf(" Examples:\n");
    printf("     Attempt Anonymous Enumeration:\n");
    printf("         %s -S ldap://127.0.0.1\n\n", Name);
    printf("     Attempt Authenticated Enumeration:\n");
    printf("         %s -S ldap://127.0.0.1 -U User@DOMAIN.COM  -B 'DC=DOMAIN,DC=COM'\n\n", Name);
        
    exit(EXIT_FAILURE);
}
void Verbose (const char * Format, ...)
{
    if (isVerbose)
    {
        va_list Arguments;
        
        va_start (Arguments, Format);
        
        vfprintf(stderr, Format, Arguments);
        
        va_end (Arguments);
    }
}
