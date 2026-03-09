/*****************************************************************************
 OSSLMLKEMKeyPair.cpp

 OpenSSL ML-KEM key-pair class
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ML_KEM
#include "log.h"
#include "OSSLMLKEMKeyPair.h"

// Set the public key
void OSSLMLKEMKeyPair::setPublicKey(OSSLMLKEMPublicKey& publicKey)
{
	pubKey = publicKey;
}

// Set the private key
void OSSLMLKEMKeyPair::setPrivateKey(OSSLMLKEMPrivateKey& privateKey)
{
	privKey = privateKey;
}

// Return the public key
PublicKey* OSSLMLKEMKeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLMLKEMKeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OSSLMLKEMKeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLMLKEMKeyPair::getConstPrivateKey() const
{
	return &privKey;
}
#endif
