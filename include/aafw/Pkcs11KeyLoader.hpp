/*
 * Pkcs11KeyLoader.hpp
 *
 *  Created on: 13/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef PKCS11KEYLOADER_HPP_
#define PKCS11KEYLOADER_HPP_

#include "aafw/KeyLoader.hpp"
#include "aafw/Pkcs11Module.hpp"

#include "cryptobase/PrivateKey.hpp"
#include "cryptobase/Certificate.hpp"

namespace aafw {

/*
 * Implements PKCS#11 key and certificate loader.
 * The constructors loads the PKCS#11 module, open a session on the specified slot, log in to it and loads the private key and certificate.
 * After that, subsequent calls of loadPrivateKey() will return the same loaded key as well subsequent calls of loadCertificate will return
 * the same loaded certificate.
 */
class AAFW_API Pkcs11KeyLoader: public KeyLoader
{
public:
	/**
	 * May throw LibraryLoadException, Pkcs11Exception in case of PKCS#11 error, NotFoundException if the key is not found or DerDecodeException if
	 * the certificate is not a valid X509 certificate (DER format).
	 * @param signAlg The digest algorithm used to sign AC
	 * @param moduleLocation The PKCS#11 module location
	 * @param keyLabel The label used to store the private key as a CKO_PRIVATE_KEY. The key will be used to sign ACs through PKCS#11 module (C_Sign)
	 * @param password The pin to login as CKU_USER on slot
	 * @param slot The slot ID to log in and search for the keyLabel
	 * @param certLabel The label used to store the matching certificate as CKO_CERTIFICATE. It must be a X509 certificate.
	 */
	Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, CK_SLOT_ID slot, const std::string& certLabel);

	/**
	 * May throw LibraryLoadException, Pkcs11Exception in case of PKCS#11 error or NotFoundException if the key is not found or DerDecodeException if
	 * the certificate is not a valid X509 certificate (DER format).
	 * @param signAlg The digest algorithm used to sign AC
	 * @param moduleLocation The PKCS#11 module location
	 * @param keyLabel The label used to store the private key as a CKO_PRIVATE_KEY. The key will be used to sign ACs through PKCS#11 module (C_Sign)
	 * @param password The pin to login as CKU_USER on slot
	 * @param slotLabel The slot label to log in and search for the keyLabel. It will find the apropriate slot ID.
	 * @param certLabel The label used to store the matching certificate as CKO_CERTIFICATE. It must be a X509 certificate.
	 */
	Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, const std::string& slotLabel, const std::string& certLabel);

	/**
	 * May throw LibraryLoadException, Pkcs11Exception in case of PKCS#11 error or NotFoundException if the key is not found.
	 * @param signAlg The digest algorithm used to sign AC
	 * @param moduleLocation The PKCS#11 module location
	 * @param keyLabel The label used to store the private key as a CKO_PRIVATE_KEY. The key will be used to sign ACs through PKCS#11 module (C_Sign)
	 * @param password The pin to login as CKU_USER on slot
	 * @param slot The slot ID to log in and search for the keyLabel
	 * @param cert The certificate matching the private key
	 */
	Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, CK_SLOT_ID slot, const cryptobase::Certificate& cert);

	/**
	 * May throw LibraryLoadException, Pkcs11Exception in case of PKCS#11 error or NotFoundException if the key is not found.
	 * @param signAlg The digest algorithm used to sign AC
	 * @param moduleLocation The PKCS#11 module location
	 * @param keyLabel The label used to store the private key as a CKO_PRIVATE_KEY. The key will be used to sign ACs through PKCS#11 module (C_Sign)
	 * @param password The pin to login as CKU_USER on slot
	 * @param slotLabel The slot label to log in and search for the keyLabel. It will find the apropriate slot ID.
	 * @param cert The certificate matching the private key
	 */

	Pkcs11KeyLoader(cryptobase::DigestAlg signAlg, const std::string& moduleLocation, const std::string& keyLabel, const std::string& password, const std::string& slotLabel, const cryptobase::Certificate& cert);

	virtual ~Pkcs11KeyLoader();

	const cryptobase::PrivateKey& loadPrivateKey() const
	{
		return privKey_;
	}
	const cryptobase::Certificate& loadCertificate() const
	{
		return cert_;
	}

	cryptobase::DigestAlg signAlgorithm() const
	{
		return signAlg_;
	}
private:
	Pkcs11KeyLoader(const Pkcs11KeyLoader&);
	Pkcs11KeyLoader& operator = (const Pkcs11KeyLoader&);

	cryptobase::DigestAlg signAlg_;
	Pkcs11Module module_;
	Pkcs11Session session_;
	cryptobase::PrivateKey privKey_;
	cryptobase::Certificate cert_;
};

} /* namespace aafw */
#endif /* PKCS11KEYLOADER_HPP_ */
