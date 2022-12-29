#ifndef MODULES_H
#define MODULES_H

#include "LDAP.h"

int     ENUM_Context            (LDAP ** LDAPConnection);

void    ENUM_Users              (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_Groups             (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_Computers          (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_Delegation         (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_POSIX              (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_GPO                (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_SPNs               (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_AdminObjects       (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_DomainAdmins       (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_PrivilegedUsers    (LDAP ** LDAPConnection, char * BaseDN);
void    ENUM_ASREP              (LDAP ** LDAPConnection, char * BaseDN);

void    ENUM_Base               (LDAP ** LDAPConnection);

#endif
