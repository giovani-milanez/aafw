/*
 * CRLPublisher.hpp
 *
 *  Criado em: 18/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef CRLPUBLISHER_HPP_
#define CRLPUBLISHER_HPP_

#include "cryptobase/CertificateRevocationList.hpp"

#include <memory>

namespace aafw {

class ACSerialLoader;

/**
 * An interface for publishing CRL.
 */
class CRLPublisher {
public:
	virtual ~CRLPublisher(){}

	/**
	 * Publishes CRL somewhere
	 */
	virtual void publish(const cryptobase::CertificateRevocationList& crl) = 0;

	/**
	 * Obtains the published CRL. If the CRL is not yet
	 * published, it may retrurn a null std::unique_ptr
	 */
	virtual std::unique_ptr<cryptobase::CertificateRevocationList> get() const = 0;

	/**
	 * Obtains the cRLDistributionPoints to append AC's extension
	 */
	virtual std::string getDistPointUrl() const = 0;

	/**
	 * Obtains the CRL validity
	 */
	virtual long getMinutesValidity() const = 0;

	/**
	 * Obtains the CRL serial loader implementation
	 */
	virtual std::unique_ptr<ACSerialLoader> getSerialLoader() const = 0;

};

} /* namespace aafw */
#endif /* CRLPUBLISHER_HPP_ */
