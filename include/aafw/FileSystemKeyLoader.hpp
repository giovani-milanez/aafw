/*
 * FileSystemKeyLoader.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef FILESYSTEMKEYLOADER_HPP_
#define FILESYSTEMKEYLOADER_HPP_

#include "aafw/Defs.h"
#include "aafw/KeyLoader.hpp"

#include "cryptobase/PrivateKey.hpp"
#include "cryptobase/Certificate.hpp"

namespace aafw {

/*
 * Implements filesystem key and certificate loader.
 */
class AAFW_API FileSystemKeyLoader: public KeyLoader
{
public:
	/**
	 * Sets both private key and certificate location and load them.
	 * May throw FileNotFoundException and EncodeException if one of the file is incorrect encoded
	 */
	FileSystemKeyLoader(cryptobase::DigestAlg signAlg, const std::string& certLocation, const std::string& privKeyLocation, const std::string& privKeyPass = "");
	virtual ~FileSystemKeyLoader();

	/**
	 * Sets the certificate location and load it.
	 * May throw FileNotFoundException and EncodeException if the file is incorrect encoded
	 */
	void setCertificate(const std::string& certLocation);

	/**
	 * Sets the private key location and load it.
	 * If the private key needs passphrase then it MUST be in PEM encoding format.
	 * May throw FileNotFoundException and EncodeException if the file is incorrect encoded
	 */
	void setPrivateKey(const std::string& privKeyLocation, const std::string& privKeyPass = "");

	const std::string& getCertLocation() const;
	const std::string& getPrivKeyLocation() const;

	/**
	 * Return the private key loaded by the constructor or set by setPrivateKey method
	 */
	const cryptobase::PrivateKey& loadPrivateKey() const;

	/**
	 * Return the certificate loaded by the constructor or set by setCertificate method
	 */
	const cryptobase::Certificate& loadCertificate() const;

	/**
	 * Return the digest algorithm
	 */
	cryptobase::DigestAlg signAlgorithm() const;

private:
	cryptobase::Certificate decodeCert(const std::string& certLocation);
	cryptobase::PrivateKey decodePriv(const std::string& privKeyLocation, const std::string& privKeyPass = "");

	cryptobase::DigestAlg signAlg_;
	cryptobase::PrivateKey privKey_;
	cryptobase::Certificate cert_;
	std::string certLocation_, privKeyLocation_;
};

inline const cryptobase::PrivateKey& FileSystemKeyLoader::loadPrivateKey() const
{
	return privKey_;
}

inline const cryptobase::Certificate& FileSystemKeyLoader::loadCertificate() const
{
	return cert_;
}

inline cryptobase::DigestAlg FileSystemKeyLoader::signAlgorithm() const
{
	return signAlg_;
}

inline const std::string& FileSystemKeyLoader::getCertLocation() const
{
	return certLocation_;
}

inline const std::string& FileSystemKeyLoader::getPrivKeyLocation() const
{
	return privKeyLocation_;
}


} /* namespace aafw */

#endif /* FILESYSTEMKEYLOADER_HPP_ */
