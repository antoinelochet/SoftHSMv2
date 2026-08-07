#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
int main()
{
        ENGINE* eg;
        const EVP_MD* EVP_GOST_34_11;

        /* Initialise OpenSSL */
        OpenSSL_add_all_algorithms();

        /* Load engines */
        OPENSSL_init_crypto(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_CONFIG, NULL);

        /* Initialise the GOST engine */
        eg = ENGINE_by_id("gost");
        if (eg == NULL)
                return 1;
        if (ENGINE_init(eg) <= 0)
                return 1;

        /* better than digest_gost */
        EVP_GOST_34_11 = ENGINE_get_digest(eg, NID_id_GostR3411_94);
        if (EVP_GOST_34_11 == NULL)
                return 1;

        /* from the openssl.cnf */
        if (ENGINE_register_pkey_asn1_meths(eg) <= 0)
                return 1;
        if (ENGINE_ctrl_cmd_string(eg,
            "CRYPT_PARAMS",
            "id-Gost28147-89-CryptoPro-A-ParamSet",
            0) <= 0)
                return 1;

        return 0;
}
