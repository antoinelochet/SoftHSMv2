/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <openssl/evp.h>
#include <openssl/objects.h>
int main()
{
    EVP_PKEY_CTX *ctx;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
    
    if (ctx == NULL)
        return 1;
    EVP_PKEY_CTX_free(ctx);
    return 0;
}