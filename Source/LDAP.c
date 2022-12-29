#include "../Headers/LDAP.h"

void LDAP_SetOption(LDAP ** LDAPConnection, int Option, void * Value)
{
    int RetCode = ldap_set_option(*LDAPConnection, Option, Value);
    
    ErrorCheck(RetCode, "Error Configuring LDAP\n");
}

void LDAP_Connect(LDAP ** LDAPConnection, char * URI, int LDAPVersion)
{
    Verbose("Connecting to %s\n", URI);
    
    ldap_initialize(&(*LDAPConnection), URI);
        
    if (LDAPConnection == NULL)
    {
        perror("Could not create LDAP Handle");
        exit(EXIT_FAILURE);
    }
    
    Verbose("Configuring the LDAP Handle\n");
    
    LDAP_SetOption(LDAPConnection, LDAP_OPT_REFERRALS, 0);
    LDAP_SetOption(LDAPConnection, LDAP_OPT_PROTOCOL_VERSION, &LDAPVersion);
}

int LDAP_Bind (LDAP ** LDAPConnection, char * Username, char * Password)
{
    if (strlen(Username) == 0)
        Verbose("Attempting Anonymous Bind\n");
    else
        Verbose("Binding as %s.\n", Username); 
    
    BerValue Credentials;
    Credentials.bv_val = Password;
    Credentials.bv_len = strlen(Password);
    
    return ldap_sasl_bind_s(*LDAPConnection, Username, LDAP_SASL_SIMPLE, &Credentials, NULL, NULL, NULL);
}

void LDAP_Enumerate (LDAP ** LDAPConnection, char * BaseDN, char * Filter, char * Attributes[])
{
    Verbose("LDAP Query: %s\n\n", Filter);
    
    LDAPMessage * Answer = LDAP_Search (LDAPConnection, LDAP_SCOPE_SUBTREE, BaseDN, Filter, Attributes);
    
    ParseAnswer(LDAPConnection, Answer);
}

void ParseAnswer(LDAP ** LDAPConnection, LDAPMessage * Answer)
{
        
    LDAPMessage     *   Entry;
    
    char            *   Attribute;  
    
    BerVarray       *   Values;
    
    BerElement      *   AttributePointer;
    
    Entry           =   ldap_first_entry(*LDAPConnection, Answer);

    if(ldap_count_entries(*LDAPConnection, Answer) == 0)
    {
        printf("\t No entries were found\n");
        return;
    }
    
    while (Entry)
    {
        char * DN = ldap_get_dn(*LDAPConnection, Entry);

        if (DN[0] != 0)
            printf("\t DN: %s\n", DN);
        
        ldap_memfree(DN);
        
        Attribute = ldap_first_attribute(*LDAPConnection, Entry, &AttributePointer);
        
        while (Attribute)
        {
            Values = ldap_get_values_len(*LDAPConnection, Entry, Attribute);
            
            for (int i = 0; i < ldap_count_values_len(Values); i++)
                printf("\t\t %s: %s\n", Attribute, Values[i] -> bv_val);
                
            ldap_value_free_len(Values);
            
            Attribute = ldap_next_attribute(*LDAPConnection, Entry, AttributePointer);  
        }
        
        ber_free(AttributePointer, 0);
        
        LDAPMessage * NextEntry = ldap_next_entry(*LDAPConnection, Entry);

        ldap_memfree(Entry);

        Entry = NextEntry;
        
    }
    
}

LDAPMessage * LDAP_Search (LDAP ** LDAPConnection, int SearchScope, char * BaseDN, char * Filter, char * Attributes[])
{
    struct timeval Timeout;
    Timeout.tv_sec = 100;
    Timeout.tv_usec = 0;
    
    LDAPMessage *   Answer;
        
    int RetCode = ldap_search_ext_s(
        *LDAPConnection, 
        BaseDN, 
        SearchScope, 
        Filter, 
        Attributes, 
        0, 
        NULL, 
        NULL, 
        &Timeout, 
        SIZE_LIMIT, 
        &Answer
    );
    
    ErrorCheck(RetCode, "Error Searching LDAP");
    
    return Answer;
}
