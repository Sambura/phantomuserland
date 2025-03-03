/* 
** Copyright 2001, Travis Geiselbrecht. All rights reserved.
** Distributed under the terms of the NewOS License.
*/
#include <ph_string.h>
#include <phantom_types.h>

char *
ph_strncat(char *dest, char const *src, size_t count)
{
	char *tmp = dest;

	if(count > 0) {
		while(*dest)
			dest++;
		while((*dest++ = *src++)) {
			if (--count == 0) {
				*dest = '\0';
				break;
			}
		}
	}

	return tmp;
}

