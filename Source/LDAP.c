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
    LDAPMessage * Answer = LDAP_Search (LDAPConnection, LDAP_SCOPE_SUBTREE, BaseDN, Filter, Attributes);
}

LDAPMessage * LDAP_Search (LDAP ** LDAPConnection, int SearchScope, char * BaseDN, char * Filter, char * Attributes[])
{
    LDAPMessage *   Answer;
    
    struct berval * Cookie              =   NULL;
    
	LDAPControl *   PageControl         =   NULL;
	LDAPControl *   ServerControls[2]   =   {NULL, NULL};
	LDAPControl **  ReturnedControls    =   NULL;
	
	char            PagingCriticality   =   'T';
	
	int             RetCode             =   0;
	
	int             ErrorCode           =   0;
	
	char            MorePages           =   0;
	
	int             TotalResults        =   0;
	
	do
	{
	    Verbose("Creating a Page Control Structure of size %d\n", PAGE_SIZE);
	    
	    RetCode = ldap_create_page_control (
	        *LDAPConnection,
	        PAGE_SIZE,
	        Cookie,
	        1,
	        &PageControl
        );
        
        ServerControls[0] = PageControl;
        
        
        Verbose("Performing Query: %s \n", Filter);
        
        RetCode = ldap_search_ext_s(
            *LDAPConnection, 
            BaseDN, 
            SearchScope, 
            Filter, 
            Attributes, 
            0, 
            ServerControls, 
            NULL, 
            NULL, 
            0, 
            &Answer
        );
        
        if ((RetCode != LDAP_SUCCESS) && (RetCode != LDAP_PARTIAL_RESULTS))
        {
            printf("Error Searching LDAP\n");
        }
        
        RetCode = ldap_parse_result(
            *LDAPConnection,
            Answer,
            &ErrorCode,
            NULL,
            NULL,
            NULL,
            &ReturnedControls,
            0
        );
        
        ErrorCheck (RetCode, "Error Parsing Result");
        
        if (Cookie != NULL && Cookie -> bv_val != NULL)
        {
            ber_bvfree(Cookie);
            Cookie = NULL;
        }
        
        int RecordsReturned = 0;
        
        RetCode = ldap_parse_page_control(
            *LDAPConnection,
            ReturnedControls,
            &RecordsReturned,
            &Cookie
        );
        
        
        if (Cookie && Cookie -> bv_val != NULL && (strlen(Cookie -> bv_val) > 0))
            MorePages = 1;
        else
            MorePages = 0;
            
        if (ReturnedControls != NULL)
        {
            ldap_controls_free(ReturnedControls);
            ReturnedControls = NULL;
        }
        
        ServerControls[0] = NULL;
        
        ldap_control_free (PageControl);
        
        PageControl = NULL;
        
        LDAPMessage * Entry = NULL;
        
        char            *   Attribute;  
        BerVarray       *   Values;
        
        for (
            Entry = ldap_first_entry(*LDAPConnection, Answer); 
            Entry != NULL; 
            Entry = ldap_next_entry(*LDAPConnection, Entry))
        {
            char * DN = ldap_get_dn(*LDAPConnection, Entry);
            BerElement      *   AttributePointer;
            
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
            
			printf("\n");

            TotalResults ++;
            
            ber_free(AttributePointer, 0);
        
        }
        
        ldap_msgfree(Answer);
          
    } while (MorePages);

}
