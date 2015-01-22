/*
 * AttributeValidator.hpp
 *
 *  Criado em: 11/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef ATTRIBUTEVALIDATOR_HPP_
#define ATTRIBUTEVALIDATOR_HPP_

#include "cryptobase/Exception.hpp"

#include <string>

namespace cryptobase {
	class Attribute;
	class Holder;
}

namespace aafw {

/**
 * An interface for validating (approve) the requesting attribute for the specified holder.
 */
class AttributeValidator
{
public:
	virtual ~AttributeValidator(){}

	/**
	 * Checks if the Holder has the privileges to obtain the attribute.
	 * You should throw an exception RejectRequestException if you want to
	 * reject it for any reason.
	 * eg, if you dont trust the holder:
	 * throw RejectRequestException("The holder is not trusted!", cryptobase::ACStatusInfo::ACFailureInfo::untrustedHolder);
	 */
	virtual void validate(const cryptobase::Attribute& attribute, const cryptobase::Holder& holder) const = 0;

};

}

#endif /* ATTRIBUTEVALIDATOR_HPP_ */
