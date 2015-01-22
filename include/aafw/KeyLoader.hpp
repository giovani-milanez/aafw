/*
 * KeyLoader.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef KEYLOADER_HPP_
#define KEYLOADER_HPP_

#include "cryptobase/DigestAlg.hpp"

namespace cryptobase {
	class PrivateKey;
	class Certificate;
}
namespace aafw {

/**
 * An interface to load a private key and it respective certificate.
 * It will be used to build and sign the ACs.
 */
class KeyLoader
{
public:
	virtual ~KeyLoader(){}

	/**
	 * The private key used to sign the ACs.
	 * Note that a reference is expected for perfomance reasons.
	 * You should load it once elsewhere and return the referene here.
	 */
	virtual const cryptobase::PrivateKey& loadPrivateKey() const = 0;

	/**
	 * The certificate corresponding to the private key used to sign the ACs.
	 * Note that a reference is expected for perfomance reasons.
	 * You should load it once elsewhere and return the referene here.
	 */
	virtual const cryptobase::Certificate& loadCertificate() const = 0;

	/**
	 * The digest algorithm used to to sign AC.
	 */
	virtual cryptobase::DigestAlg signAlgorithm() const = 0;
};

}

#endif /* KEYLOADER_HPP_ */
