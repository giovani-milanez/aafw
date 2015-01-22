/*
 * AllowValidator.hpp
 *
 *  Criado em: 19/03/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef ALLOWVALIDATOR_HPP_
#define ALLOWVALIDATOR_HPP_

#include "aafw/Defs.h"

#include "aafw/AttributeValidator.hpp"

namespace aafw {

/**
 * Always allow the attribute to be
 * issued for the holder present on request.
 */
class AAFW_API AllowValidator : public AttributeValidator
{
public:
	AllowValidator();

	void validate(const cryptobase::Attribute& attribute, const cryptobase::Holder& holder) const;
};


}

#endif /* ALLOWVALIDATOR_HPP_ */
