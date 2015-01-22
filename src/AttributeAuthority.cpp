/*
 * AttributeAuthority.cpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/AttributeAuthority.hpp"
#include "aafw/TransportServer.hpp"
#include "aafw/KeyLoader.hpp"
#include "aafw/ACStore.hpp"
#include "aafw/ACSerialLoader.hpp"
#include "aafw/CRLPublisher.hpp"
#include "aafw/FileSystemACSerialLoader.hpp"
#include "aafw/DefaultACTemplate.hpp"
#include "aafw/CRLHouseKeep.hpp"

#include "cryptobase/Certificate.hpp"
#include "cryptobase/CertificateRevocationList.hpp"
#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/TimeFunctions.hpp"
#include "cryptobase/AttributeCertificateSearchInfo.hpp"
#include "cryptobase/AttributeCertificateRevInfo.hpp"

#include "Poco/DateTime.h"

#include <iostream>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace aafw {

CRYPTOBASE_IMPLEMENT_EXCEPTION(AlreadyRegisteredException, cryptobase::Exception, "Already Registered")
CRYPTOBASE_IMPLEMENT_EXCEPTION(NoSuchException, cryptobase::Exception, "No Such Element")

AttributeAuthority::AttributeAuthority() :
		oi_(),
		factory_(nullptr),
		acStore_(nullptr),
		keyLoader_(nullptr),
		serialLoader_(nullptr),
		transportServer_(nullptr),
		validators_(),
		publishers_(),
		denyUnknownAttributes_(false),
		denyEmptyAttributes_(false),
		unkownAttributeMessage_("Unknown attribute requested"),
		emptyAttributeMessage_("No attribute requested")
{
	addSubsystem(new CRLHouseKeep);
}

AttributeAuthority::~AttributeAuthority()
{
}

cryptobase::AttributeCertificateResp AttributeAuthority::handleRequest(const cryptobase::AttributeCertificateReq& req)
{
	auto print = [](const std::string& str) { std::cout << str << std::endl; };
	print("handleRequest");
	try
	{
		std::vector<cryptobase::AttributeCertificate> acs;
		if(req.getReqType() == cryptobase::AttributeCertificateReq::ReqType::ISSUE)
		{
			auto reqIssuePtr = req.getIssueInfo();
			if(reqIssuePtr == nullptr)
				throw RejectRequestException("Request of type 'issue' but no AttributeCertificateIssueInfo present", cryptobase::ACStatusInfo::ACFailureInfo::badDataFormat);

			acs.push_back(issueAttributeCertificate(*reqIssuePtr.get()));

		}
		else if(req.getReqType() == cryptobase::AttributeCertificateReq::ReqType::REVOKE)
		{
			print("Requisicao do tipo REVOKE");
			auto revInfo = req.getRevInfo();

			auto it = publishers_.find(revInfo->getAttributeOid().getOidStr());
			if(it == publishers_.end())
			{
				print("Nao encontrado publicador para atributo "+revInfo->getAttributeOid().getOidStr());
				throw RejectRequestException("No revocation supported for attribute OID "+revInfo->getAttributeOid().getOidStr(), cryptobase::ACStatusInfo::ACFailureInfo::unsupportedAttribute);
			}
			print("Encontrado publicador para atributo "+revInfo->getAttributeOid().getOidStr());
			std::vector<cryptobase::ObjectIdentifier> vec;
			vec.push_back(revInfo->getAttributeOid());

			print("Buscando ACs");
			auto acs = acStore_->retrieveAc(revInfo->getHolder(), vec);
			
			for(auto ac : acs)
			{
				std::string serial = ac.getInfo().getSerialString();
				print("Revogando AC serial "+serial);
				revoke(it->second, serial);
			}
		}
		else if(req.getReqType() == cryptobase::AttributeCertificateReq::ReqType::SEARCH)
		{
			auto searchInfoPtr = req.getSearchInfo();
			if(searchInfoPtr == nullptr)
				throw RejectRequestException("Request of type 'search' but no AttributeCertificateSearchInfo present", cryptobase::ACStatusInfo::ACFailureInfo::badDataFormat);

			acs = searchAttributeCertificate(*searchInfoPtr.get());
		}
		else
			throw RejectRequestException("Request type must be 'search'("+std::to_string(cryptobase::AttributeCertificateReq::ReqType::SEARCH)+"), "
			"'revoke'("+std::to_string(cryptobase::AttributeCertificateReq::ReqType::REVOKE)+")"+" or 'issue'("+std::to_string(cryptobase::AttributeCertificateReq::ReqType::ISSUE)+")", cryptobase::ACStatusInfo::ACFailureInfo::badDataFormat);

		return cryptobase::AttributeCertificateResp(acs);
	}
	catch(const RejectRequestException& ex)
	{
		return cryptobase::AttributeCertificateResp(ex.message(), (cryptobase::ACStatusInfo::ACFailureInfo)ex.code());
	}
	catch(const cryptobase::Exception& ex)
	{
		return cryptobase::AttributeCertificateResp(ex.message(), cryptobase::ACStatusInfo::ACFailureInfo::systemFailure);
	}
	catch(const std::exception& ex)
	{
		return cryptobase::AttributeCertificateResp(std::string(ex.what()), cryptobase::ACStatusInfo::ACFailureInfo::systemFailure);
	}
	catch(...)
	{
		return cryptobase::AttributeCertificateResp("System Failure", cryptobase::ACStatusInfo::ACFailureInfo::systemFailure);
	}
}

void AttributeAuthority::revoke(std::unique_ptr<CRLPublisher>& crlPublisher, const std::string& acSerial)
{
	Poco::DateTime nowDt;
	time_t now = nowDt.timestamp().epochTime();
	cryptobase::CertificateRevocationList crl(X509_CRL_new());
	crl.setVersion(1);
	auto cert = keyLoader_->loadCertificate();
	crl.setIssuer(cert);
	crl.setLastUpdate(now);
	crl.setNextUpdate(now + (crlPublisher->getMinutesValidity() *60));
	crl.setSerialNumber(crlPublisher->getSerialLoader()->nextSerial());
	if(!acSerial.empty())
	{
		crl.addRevoked(cryptobase::RevokedCertificate::fromSerial(acSerial,		cryptobase::RevokedCertificate::CRLReason::privilegeWithdrawn));
	}

	// grab revoked certificates from old CRL, to append
	// in the new one
	auto oldCrl = crlPublisher->get();
	if(oldCrl != nullptr)
		crl.appendRevokedCertificates(*oldCrl.get());
	
	crl.sign(keyLoader_->loadPrivateKey(), keyLoader_->signAlgorithm());

	crlPublisher->publish(crl);
}

void AttributeAuthority::registerValidator(const std::string& oid, AttributeValidator* validator)
{
	if(validator == nullptr)
		throw cryptobase::NullPointerException("Null AttributeValidator given on AttributeAuthority::registerValidator");

	auto it = validators_.find(oid);

	if(it != validators_.end())
		throw AlreadyRegisteredException("Validator for attribute '"+oid+"' is already registered");

	validators_[oid] = std::unique_ptr<AttributeValidator>(validator);
}

void AttributeAuthority::unregisterValidator(const std::string& oid)
{
	auto it = validators_.find(oid);
	if(it == validators_.end())
		throw NoSuchException("Validator for attribute '"+oid+"' isnt registered");

	validators_.erase(oid);
}

void AttributeAuthority::registerCRLPublisher(const std::string& oid, CRLPublisher *publisher)
{
	if(publisher == nullptr)
		throw cryptobase::NullPointerException("Null AttributeValidator given on AttributeAuthority::registerValidator");

	auto it = publishers_.find(oid);

	if(it != publishers_.end())
		throw AlreadyRegisteredException("CRL Publisher for attribute '"+oid+"' is already registered");

	publishers_[oid] = std::unique_ptr<CRLPublisher>(publisher);
}

void AttributeAuthority::unregisterCRLPublisher(const std::string& oid)
{
	auto it = publishers_.find(oid);
	if(it == publishers_.end())
		throw NoSuchException("CRL Publisher for attribute '"+oid+"' isnt registered");

	publishers_.erase(oid);
}

void AttributeAuthority::registerAttributeCertificateTemplate(int templateId, ACTemplate *acTemplate)
{
	if(acTemplate == nullptr)
		throw cryptobase::NullPointerException("Null ACTemplate given on AttributeAuthority::registerAttributeCertificateTemplate");

	auto it = templates_.find(templateId);

	if(it != templates_.end())
		throw AlreadyRegisteredException("Attribute Certificate Template of ID '"+std::to_string(templateId)+"' is already registered");

	templates_[templateId] = std::unique_ptr<ACTemplate>(acTemplate);
}

void AttributeAuthority::unregisterAttributeCertificateTemplate(int templateId)
{
	auto it = templates_.find(templateId);
	if(it == templates_.end())
		throw NoSuchException("Attribute Certificate Template of ID '"+std::to_string(templateId)+"' isnt registered");

	templates_.erase(templateId);
}

void AttributeAuthority::handleTransportError(const std::exception& ex)
{
	const cryptobase::Exception *e = dynamic_cast<const cryptobase::Exception*>(&ex);
	const Poco::Exception *ePoco = dynamic_cast<const Poco::Exception*>(&ex);
	if(e)
		std::cout << e->displayText() << std::endl;
	else if(ePoco)
		std::cout << e->displayText() << std::endl;
	else
		std::cout << std::string(ex.what()) << std::endl;
}

void AttributeAuthority::initialize(Poco::Util::Application& self)
{	
	factory_ = getSystemFactory();
	acStore_ = factory_->getACStore();
	keyLoader_ = factory_->getKeyLoader();
	serialLoader_ = factory_->getACSerialLoader();
	transportServer_ = factory_->getTransportServer();

	setup();

	transportServer_->start();

	ServerApplication::initialize(self);
}

void AttributeAuthority::uninitialize()
{
	transportServer_->stop();
	ServerApplication::uninitialize();
}

void AttributeAuthority::defineOptions(Poco::Util::OptionSet& options)
{
	stopOptionsProcessing();
}

int AttributeAuthority::main(const std::vector<std::string>& args)
{
	waitForTerminationRequest();
	return Application::EXIT_OK;
}

cryptobase::AttributeCertificate AttributeAuthority::issueAttributeCertificate(const cryptobase::AttributeCertificateIssueInfo& issueInfo)
{
	auto print = [](const std::string& str) { std::cout << str << std::endl; };

	std::vector<cryptobase::Attribute> attrs;
	const ACTemplate *templateFound = nullptr;

	cryptobase::Holder holder = issueInfo.getHolder();
	auto templateId = issueInfo.getTemplateId();

	if(templateId != nullptr)
	{
		print("template id informado");
		auto it = templates_.find(*templateId.get());
		if(it == templates_.end())
			throw RejectRequestException("The template ID "+std::to_string(*templateId.get())+" is not known", cryptobase::ACStatusInfo::ACFailureInfo::unsupportedTemplate);

		templateFound = it->second.get();
		for(auto& templateAttr : templateFound->getAttributes())
		{
			templateAttr.second->validate(templateAttr.first, holder);
			// attribute successfully validated, lets add it to the attribute certificate
			attrs.push_back(templateAttr.first);
		}
	}
	else
	{
		print("sem template id");
		if(issueInfo.getValidity() == nullptr)
			throw RejectRequestException("The validity must be provided", cryptobase::ACStatusInfo::ACFailureInfo::badRequest);

		if(issueInfo.getAttributes() == nullptr || issueInfo.getAttributes()->empty())
			throw RejectRequestException("The attributes must be provided", cryptobase::ACStatusInfo::ACFailureInfo::badRequest);

		print("obtendo atributos");
		auto issurAttrs = issueInfo.getAttributes();
		if(issurAttrs != nullptr)
		{
			for(auto attr : *issurAttrs.get())
			{
				print("obtendo validadro do atributo "+attr.getOid().getOidStr());
				auto it = validators_.find(attr.getOid().getOidStr());
				if(it == validators_.end())
				{
					print("validador nao encontrado");
					if(denyUnknownAttributes_)
						throw RejectRequestException(unkownAttributeMessage_,					cryptobase::ACStatusInfo::ACFailureInfo::unsupportedAttribute);
				}
				else
				{
					print("validador encontrado. Validando...");
					it->second->validate(attr, holder);
					print("Atributo validado!");
				}
			}
		}
		// all requested attributes are successfully validated.
		// lets add it to the attribute certificate
		print("Copiando atributos da requisicao");
		attrs = *issurAttrs.get();		
	}
	print("Copiando extensao");
	std::vector<cryptobase::Extension> exts;
	if(templateFound != nullptr)
		exts = templateFound->getExtensions(holder);
	else
	{
		if(issueInfo.getExtensions() != nullptr)
			exts = *issueInfo.getExtensions().get();
	}

	print("adicionando dist point");
	std::vector<std::string> distPoints;
	for(auto attr : attrs)
	{
		auto it = publishers_.find(attr.getOid().getOidStr());
		if(it != publishers_.end())
		{
			print("dist point para atributo "+attr.getOid().getOidStr()+" eh "+it->second->getDistPointUrl());
			distPoints.push_back(it->second->getDistPointUrl());
		}
	}
	if(distPoints.empty())
	{
		exts.push_back(cryptobase::Extension::createNoRevAvail());
	}
	else
	{
		exts.push_back(cryptobase::Extension::createDistPoint(distPoints));
	}
	print("Criando ac!");
	cryptobase::AttributeCertificate ac(keyLoader_->loadPrivateKey(),
													keyLoader_->signAlgorithm(),
													holder,
													keyLoader_->loadCertificate().getSubject(),
													serialLoader_->nextSerial(),
													templateFound != nullptr ? templateFound->getValidity(holder) : *issueInfo.getValidity().get(),
													attrs,
													exts
													);
	acStore_->saveAc(ac);
	return ac;
}
std::vector<cryptobase::AttributeCertificate> AttributeAuthority::searchAttributeCertificate(const cryptobase::AttributeCertificateSearchInfo& searchInfo)
{
	auto attrs = searchInfo.getAttributesOid();
	if(attrs != nullptr && attrs->size() > 0)
		return acStore_->retrieveAc(searchInfo.getHolder(), *attrs.get());
	else
		return acStore_->retrieveAc(searchInfo.getHolder());
}

} /* namespace aafw */
