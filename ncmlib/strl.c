/* strl.c - strlcpy/strlcat implementation
 * Time-stamp: <2010-11-01 17:20:05 nk>
 *
 * (c) 2003-2010 Nicholas J. Kain <njkain at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <unistd.h>
#include "strl.h"

#ifndef HAVE_STRLCPY
size_t strlcpy (char *dest, char *src, size_t size)
{
	register unsigned int i = 0;

	if (size > 0) {
		size--;
		for (i=0; size > 0 && src[i] != '\0'; ++i, size--)
			dest[i] = src[i];

		dest[i] = '\0';
	}
	while (src[i++]);

	return i;
}
#endif /* HAVE_STRLCPY */

#ifndef HAVE_STRLCAT
size_t strlcat (char *dest, char *src, size_t size)
{
	register char *d = dest;

	for (; size > 0 && *d != '\0'; size--, d++);
	return (d - dest) + strlcpy(d, src, size);
}
#endif /* HAVE_STRLCAT */

