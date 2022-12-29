#include "../Headers/Modules.h"

int ENUM_Context(LDAP ** LDAPConnection)
{
    BerValue * Authorisation;

    Verbose("Executing Whoami\n");
    
    int RetCode = ldap_whoami_s(*LDAPConnection, &Authorisation, NULL, NULL);
    ErrorCheck(RetCode, "Error checking user context: ");
    
    if (Authorisation != NULL)
    {
        printf("Executing LDAP Queries as: %s\n\n", Authorisation -> bv_val);
        ldap_memfree(Authorisation);
    }
    
    return RetCode;
}

void ENUM_Users (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter       =   "(&(objectClass=User)(objectCategory=Person))";
    
    char * Attributes[] = { "cn", "sAMACcountName", "userPrincipalName", "description", "badpwdcount", NULL };
    
    printf("[+] Enumerating Users: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_Groups (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter       =   "(objectClass=group)";
    
    char * Attributes[] = { "cn", "sAMACcountName", NULL };
    
    printf("[+] Enumerating Groups: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_Computers (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(objectClass=computer)";
    
    char * Attributes[]         =   { "operatingSystem", "operatingSystemVersion", "dNSHostName", "msDS-KeyCredentialLink", "description", NULL };
    
    printf("[+] Enumerating Computers: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_Delegation(LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(&(|(UserAccountControl:1.2.840.113556.1.4.803:=16777216)(UserAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(UserAccountControl:1.2.840.113556.1.4.803:=8192)))";
    
    char * Attributes[]         =   { "operatingSystem", "operatingSystemVersion", "dNSHostName", "objectCategory", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo", NULL };
    
    printf("[+] Enumerating Unconstrained Delegation: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_POSIX (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(objectClass=posixAccount)";
       
    char * Attributes[]         =   { "sshPublicKey", NULL };
    
    printf("[+] Enumerating POSIX Users: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_GPO (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(objectClass=groupPolicyContainer)";
        
    char * Attributes[]         =   { "displayName", "gPCFileSysPath", NULL };
    
    printf("[+] Enumerating Group Policies: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_SPNs (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))";
    
    char * Attributes[]         =   { "cn", "sAMAccountName", "userPrincipalName", NULL };
    
    printf("[+] Enumerating Service Principal Names: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_ASREP (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
    
    char * Attributes[]         =   { "cn", "sAMAccountName", "userPrincipalName", NULL };
    
    printf("[+] Enumerating User Accounts not Required to Pre-Authenticate: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_AdminObjects (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(adminCount=1)";
    
    char * Attributes[]         =   { "cn", NULL };
    
    printf("[+] Enumerating Admin Objects: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_DomainAdmins (LDAP ** LDAPConnection, char * BaseDN)
{
    char * AdminGroups[]  =   {
        "Domain Admins",
	    "Domain-Admins",
	    "Domain Administrators",
	    "Domain-Administrators",
	    "Domänen Admins",
	    "Domänen-Admins",
	    "Domain Admins",
	    "Domain-Admins",
	    "Domänen Administratoren",
	    "Domänen-Administratoren",
	    NULL
    };
    
    char Filter [250];
            
    char * Attributes[]         =   { "cn", NULL };
    char ** ArrayPointer        =   AdminGroups;
    
    for (char * AdminGroup = *ArrayPointer; AdminGroup; AdminGroup = *++ArrayPointer)
    {
        printf("[+] Enumerating Domain Admin Group: %s: \n", AdminGroup);
        
        snprintf(Filter, 250, "(&(objectClass=user)(|(memberof:1.2.840.113556.1.4.1941:=CN=%s,CN=Users,%s)))", AdminGroup, BaseDN);
        LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
    }
}

void ENUM_PrivilegedUsers (LDAP ** LDAPConnection, char * BaseDN)
{
    char * AdminGroups[]        =   {
	    "Administrators", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators", "Server Management", "Konten-Operatoren", "Sicherungs-Operatoren", "Server-Operatoren", "Schema-Admins", NULL
    };
    
    char Filter [250];
        
    char * Attributes[]         =   { "cn", NULL };
    
    char ** ArrayPointer        =   AdminGroups;
    
    for (char * AdminGroup = *ArrayPointer; AdminGroup; AdminGroup = *++ArrayPointer)
    {
        printf("[+] Enumerating Privileged Users Group: %s\n", AdminGroup);
        
        snprintf(Filter, 250, "(&(objectClass=user)(|(memberof:1.2.840.113556.1.4.1941:=CN=%s,CN=Users,%s)))", AdminGroup, BaseDN);
        LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
    }
}

void ENUM_Base (LDAP ** LDAPConnection)
{
    printf("[+] Enumerating Metadata: \n");
    
    char * Filter               =   "(objectClass=*)";
    
    char * Attributes[]         =   { "defaultNamingContext", "domainFunctionality", "forestFunctionality", "domainControllerFunctionality", "dnsHostName", NULL };
        
    LDAPMessage * Answer = LDAP_Search (LDAPConnection, LDAP_SCOPE_BASE, "", Filter, Attributes);
    
    ParseAnswer(LDAPConnection, Answer);
}

