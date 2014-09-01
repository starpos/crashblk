#ifndef SIZE_LIST_H
#define SIZE_LIST_H
#include <linux/string.h>

static inline bool parse_u64(const char *p, const char **next_p, u64 *size_p)
{
	u64 c = 0;
	const char *q;
	if (!p) return false;
	q = strchr(p, ',');
	if (!q) q = p + strlen(p);
	while (p < q) {
		if ('0' <= *p && *p <= '9') {
			c *= 10;
			c += (u64)(*p - '0');
		} else {
			switch (*p) {
			case 't': case 'T': c <<= 10;
			case 'g': case 'G': c <<= 10;
			case 'm': case 'M': c <<= 10;
			case 'k': case 'K': c <<= 10;
				break;
			default:
				return false;
			}
		}
		p++;
	}
	*size_p = c;
	*next_p = (*q == ',' ? q + 1 : NULL);
	return true;
}

#endif /* SIZE_LIST_H */
