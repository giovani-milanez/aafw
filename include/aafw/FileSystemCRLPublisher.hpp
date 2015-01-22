/*
 * FileSystemCRLPublisher.hpp
 *
 *  Criado em: 18/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef FILESYSTEMCRLPUBLISHER_HPP_
#define FILESYSTEMCRLPUBLISHER_HPP_

#include "aafw/Defs.h"
#include "aafw/CRLPublisher.hpp"

#include "cryptobase/EncodingType.hpp"

namespace aafw {

/**
 * Publisher and fetch CRL from file system.
 *
 */
class AAFW_API FileSystemCRLPublisher: public CRLPublisher {
public:
	FileSystemCRLPublisher(long crlValidity, const std::string& distPoint, const std::string& filePath, cryptobase::EncodingType encoding = cryptobase::EncodingType::PEM);
	virtual ~FileSystemCRLPublisher();

	/**
	 * Publishes CRL into filesystem
	 */
	void publish(const cryptobase::CertificateRevocationList& crl);

	/**
	 * Obtains the published CRL
	 */
	std::unique_ptr<cryptobase::CertificateRevocationList> get() const;

	/**
	 * Obtains the cRLDistributionPoints to append AC's extension
	 */
	std::string getDistPointUrl() const;

	long getMinutesValidity() const;

	std::unique_ptr<ACSerialLoader> getSerialLoader() const;

private:
	std::string pathToSave_, distPoint_;
	cryptobase::EncodingType encoding_;
	long crlValidity_;
};

} /* namespace aafw */
#endif /* FILESYSTEMCRLPUBLISHER_HPP_ */
