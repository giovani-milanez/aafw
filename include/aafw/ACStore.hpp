/*
 * ACStore.hpp
 *
 *  Created on: 10/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef ACSTORE_HPP_
#define ACSTORE_HPP_

#include "cryptobase/ObjectIdentifier.hpp"
#include <vector>

namespace cryptobase {
	class AttributeCertificate;
	class Holder;
}

namespace aafw {

/**
 * An interface to store attribute certificates.
 */
class ACStore
{
public:
	virtual ~ACStore(){}

	/**
	 * Stores the AC somewhere, depends on its implementation. Examples are: filesystem, database, LDAP.
	 * This method will be called right after the AC is sucessfully constructed
	 * and before it get send back to the requester.
	 * @param ac The AC to store.
	 */
	virtual void saveAc(const cryptobase::AttributeCertificate& ac) = 0;
	/**
	 * Finds the attribute certificates issued for the holder in the store.
	 */
	virtual std::vector<cryptobase::AttributeCertificate> retrieveAc(const cryptobase::Holder& holder) = 0;

	/**
	 * Finds the attribute certificates issued for the holder in the store containing ANY of the attrsOid.
	 */
	virtual std::vector<cryptobase::AttributeCertificate> retrieveAc(const cryptobase::Holder& holder, const std::vector<cryptobase::ObjectIdentifier>& attrsOid) = 0;

	/**
 	 * Finds the attribute certificate by its serial.
	 * MUST throw cryptobase::NotFoundException if not found
	 */
	virtual cryptobase::AttributeCertificate retrieveAc(const std::string& acSerial) = 0;
	
};

}


#endif /* ACSTORE_HPP_ */
