#include "../Headers/Modules.h"

char * UserAttributes[] = 
{ 
    "cn", 
	"objectCategory",
    "SAMaccountName", 
    "UserPrincipalName", 
    "Description", 
    "Badpwdcount", 
    "servicePrincipalName",
    NULL 
};

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
    
    printf("\n[+] Enumerating Users: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, UserAttributes); 
}

void ENUM_PasswordExpiry (LDAP ** LDAPConnection, char * BaseDN)
{
	char * Filter		=	"(&(objectCategory=Person)(userAccountControl:1.2.840.113556.1.4.803:=65536))";

    printf("\n[+] Enumerating Users Accounts which never Expire: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, UserAttributes); 

}
void ENUM_Groups (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter       =   "(objectClass=group)";
    
    char * Attributes[] = { "cn", "sAMACcountName", NULL };
    
    printf("\n[+] Enumerating Groups: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_Computers (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(objectClass=computer)";
    
    char * Attributes[]         =   { "operatingSystem", "operatingSystemVersion", "dNSHostName", "msDS-KeyCredentialLink", "description", NULL };
    
    printf("\n[+] Enumerating Computers: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_Delegation(LDAP ** LDAPConnection, char * BaseDN)
{
	/*
		Query Description:
			User Account Control Value 16777216 - Check for Trusted to Authenticated for Delegation User Accounts 	- TRUSTED_TO_AUTH_FOR_DELEGATION
			User Account Control Value 524288   - Check for Unconstrained Delegation User Accounts 					- TRUSTED_FOR_DELEGATION
			msDS-Allowed-To-Delegate-To         - Configures a service so that it can obtain Constrained Delegation Service Tickets
			msDS-AllowedToActOnBehalfOfOtherIdentity - Determines if a requestor has permission to act on behalf of other identities
	*/
		
    char * Filter               =   
		"(&"
			"(|"
				"(UserAccountControl:1.2.840.113556.1.4.803:=16777216)"
				"(UserAccountControl:1.2.840.113556.1.4.803:=524288)"
				"(msDS-AllowedToDelegateTo=*)"
				"(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
			")"
			"(!(UserAccountControl:1.2.840.113556.1.4.803:=2))"
			"(!(UserAccountControl:1.2.840.113556.1.4.803:=8192))"
		")";
    
    char * Attributes[]         =   { "operatingSystem", "operatingSystemVersion", "dNSHostName", "objectCategory", "msDS-AllowedToActOnBehalfOfOtherIdentity", "msDS-AllowedToDelegateTo", NULL };
    
    printf("\n[+] Enumerating Delegations: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes); 
}

void ENUM_POSIX (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(objectClass=posixAccount)";
       
    char * Attributes[]         =   { "sshPublicKey", NULL };
    
    printf("\n[+] Enumerating POSIX Users: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_GPO (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(objectClass=groupPolicyContainer)";
        
    char * Attributes[]         =   { "displayName", "gPCFileSysPath", NULL };
    
    printf("\n[+] Enumerating Group Policies: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_SPNs (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))";
    
    printf("\n[+] Enumerating Service Principal Names: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, UserAttributes);
}

void ENUM_ASREP (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))";
    
    printf("\n[+] Enumerating User Accounts not Required to Pre-Authenticate: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, UserAttributes);
}

void ENUM_AdminObjects (LDAP ** LDAPConnection, char * BaseDN)
{
    char * Filter               =   "(adminCount=1)";
    
    char * Attributes[]         =   { "cn", NULL };
    
    printf("\n[+] Enumerating Admin Objects: \n");
    
    LDAP_Enumerate(LDAPConnection, BaseDN, Filter, Attributes);
}

void ENUM_PrivilegedUsers (LDAP ** LDAPConnection, char * BaseDN)
{
    char  * AdminGroups[]        =   {
	   "Domain Admins",  "Administrators", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators", "Server Management" , NULL
    };
    
    char Filter [250];
    
    for (char ** ArrayPointer = AdminGroups; *ArrayPointer; ArrayPointer++)
    {
        printf("\n[+] Enumerating Privileged Users Group: %s\n", *ArrayPointer);
        
        snprintf(Filter, 250, "(&(objectClass=user)(|(memberof:1.2.840.113556.1.4.1941:=CN=%s,CN=Users,%s)))", *ArrayPointer, BaseDN);
        LDAP_Enumerate(LDAPConnection, BaseDN, Filter, UserAttributes);
    }
}

void ENUM_AdminCount (LDAP ** LDAPConnection)
{
    printf("\n[+] Enumerating Admins: \n");
    
    char * Filter               =   "(&(objectClass=*)(adminCount=1))";

    LDAPMessage * Answer = LDAP_Search (LDAPConnection, LDAP_SCOPE_BASE, "", Filter, UserAttributes);
}

void ENUM_Base (LDAP ** LDAPConnection)
{
    printf("\n[+] Enumerating Metadata: \n");
    
    char * Filter               =   "(objectClass=*)";
    
    char * Attributes[]         =   { "defaultNamingContext", "domainFunctionality", "forestFunctionality", "domainControllerFunctionality", "dnsHostName", NULL };

    LDAPMessage * Answer = LDAP_Search (LDAPConnection, LDAP_SCOPE_BASE, "", Filter, Attributes);
}

