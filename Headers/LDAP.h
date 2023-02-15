#ifndef LDAP_H
#define LDAP_H

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

#include "Errors.h"

#define PAGE_SIZE 500

void                LDAP_SetOption          (LDAP ** LDAPConnection, int Option, void * Value);

void                LDAP_Connect            (LDAP ** LDAPConnection, char * URI, int LDAPVersion);
int                 LDAP_Bind               (LDAP ** LDAPConnection, char * Username, char * Password);

void                LDAP_Enumerate          (LDAP ** LDAPConnection, char * BaseDN, char * Filter, char * Attributes[]);

LDAPMessage *       LDAP_Search             (LDAP ** LDAPConnection, int SearchScope, char * BaseDN, char * Filter, char * Attributes[]);


#endif
