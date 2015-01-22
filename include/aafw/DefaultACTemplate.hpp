/*
 * DefaultACTemplate.hpp
 *
 *  Criado em: 02/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef DEFAULTACTEMPLATE_HPP_
#define DEFAULTACTEMPLATE_HPP_

#include "aafw/ACTemplate.hpp"
#include "aafw/Exception.hpp"
#include "aafw/AllowValidator.hpp"

#include "cryptobase/AttributeCertificateIssueInfo.hpp"
#include "cryptobase/ACStatusInfo.hpp"

namespace aafw {

class DefaultACTemplate : public ACTemplate
{
public:
	DefaultACTemplate(const cryptobase::AttributeCertificateIssueInfo& issueInfo) :
		issueInfo_(issueInfo){}

	cryptobase::AttributeCertificateValidity getValidity(const cryptobase::Holder& holder) const
	{
		if(issueInfo_.getValidity() == nullptr)
			throw RejectRequestException("The validity must be provided", cryptobase::ACStatusInfo::ACFailureInfo::badRequest);

		return *issueInfo_.getValidity().get();
	}
	std::vector<std::pair<cryptobase::Attribute, std::unique_ptr<AttributeValidator>>> getAttributes() const
	{
		if(issueInfo_.getAttributes() == nullptr)
			throw RejectRequestException("The attributes must be provided", cryptobase::ACStatusInfo::ACFailureInfo::badRequest);

		std::vector<std::pair<cryptobase::Attribute, std::unique_ptr<AttributeValidator>>> result;		
		result.reserve(issueInfo_.getAttributes()->size());
		for(auto attr : *issueInfo_.getAttributes().get())
		{
			result.push_back(std::make_pair(attr, std::unique_ptr<AttributeValidator>(new AllowValidator)));
		}
		return result;
	}
	std::vector<cryptobase::Extension> getExtensions(const cryptobase::Holder& holder) const
	{
		if(issueInfo_.getExtensions() == nullptr)
			return std::vector<cryptobase::Extension>();
		return *issueInfo_.getExtensions().get();
	}
private:
	cryptobase::AttributeCertificateIssueInfo issueInfo_;

};

} /* namespace aafw */

#endif /* DEFAULTACTEMPLATE_HPP_ */
