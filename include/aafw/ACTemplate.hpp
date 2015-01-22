/*
 * ACTemplate.hpp
 *
 *  Criado em: 02/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef ACTEMPLATE_HPP_
#define ACTEMPLATE_HPP_

#include "cryptobase/AttributeCertificateValidity.hpp"
#include "cryptobase/Attribute.hpp"
#include "cryptobase/Extension.hpp"
#include "cryptobase/Holder.hpp"

#include <memory>

namespace aafw {

class AttributeValidator;

class ACTemplate
{
public:
	virtual ~ACTemplate(){}
	virtual cryptobase::AttributeCertificateValidity getValidity(const cryptobase::Holder& holder) const = 0;
	virtual std::vector<std::pair<cryptobase::Attribute, std::unique_ptr<AttributeValidator>>> getAttributes() const = 0;
	virtual std::vector<cryptobase::Extension> getExtensions(const cryptobase::Holder& holder) const = 0;
};

}

#endif /* ACTEMPLATE_HPP_ */
