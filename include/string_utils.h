#ifndef LIMINAL_STRING_UTILS_H
#define LIMINAL_STRING_UTILS_H

#include <stddef.h>
#include <string.h>

static inline size_t liminal_strlcpy(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0U) {
        return 0U;
    }

    const char *safe_src = src ? src : "";
    size_t src_len = strlen(safe_src);
    size_t copy_len = (src_len < (dst_size - 1U)) ? src_len : (dst_size - 1U);
    if (copy_len > 0U) {
        memcpy(dst, safe_src, copy_len);
    }
    dst[copy_len] = '\0';
    return src_len;
}

#endif
