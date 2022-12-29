#ifndef ERRORS_H
#define ERRORS_H

#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

void ErrorCheck (int Value, char * Message);
void Verbose    (const char * Format, ...);

#endif
