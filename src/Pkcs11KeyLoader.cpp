/*
 * Pkcs11KeyLoader.cpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/Pkcs11KeyLoader.hpp"

namespace aafw {

Pkcs11KeyLoader::Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, CK_SLOT_ID slot, const std::string& certLabel) :
	signAlg_(signAlg),
	module_(moduleLocation),
	session_(module_.openSession(slot, password)),
	privKey_(session_.extractPkcs11Key(session_.findObject(keyLabel, CKO_PRIVATE_KEY))),
	cert_(session_.extractCertificate(session_.findObject(certLabel, CKO_CERTIFICATE)))
{

}

Pkcs11KeyLoader::Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, const std::string& slotLabel, const std::string& certLabel) :
	signAlg_(signAlg),
	module_(moduleLocation),
	session_(module_.openSession(slotLabel, password)),
	privKey_(session_.extractPkcs11Key(session_.findObject(keyLabel, CKO_PRIVATE_KEY))),
	cert_(session_.extractCertificate(session_.findObject(certLabel, CKO_CERTIFICATE)))
{

}


Pkcs11KeyLoader::Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, CK_SLOT_ID slot, const cryptobase::Certificate& cert) :
	signAlg_(signAlg),
	module_(moduleLocation),
	session_(module_.openSession(slot, password)),
	privKey_(session_.extractPkcs11Key(session_.findObject(keyLabel, CKO_PRIVATE_KEY))),
	cert_(cert)
{
}

Pkcs11KeyLoader::Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, const std::string& slotLabel, const cryptobase::Certificate& cert) :
	signAlg_(signAlg),
	module_(moduleLocation),
	session_(module_.openSession(slotLabel, password)),
	privKey_(session_.extractPkcs11Key(session_.findObject(keyLabel, CKO_PRIVATE_KEY))),
	cert_(cert)
{
}

Pkcs11KeyLoader::~Pkcs11KeyLoader()
{
}



} /* namespace aafw */
