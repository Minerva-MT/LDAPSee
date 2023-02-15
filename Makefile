
ldapsee:
	$(CC) -ggdb ldapsee.c Source/*.c -o ldapsee -lldap -llber
