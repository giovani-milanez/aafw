/*
 * ThriftServer.cpp
 *
 *  Criado em: 09/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "aafw/ThriftServer.hpp"
#include "aafw/AttributeAuthority.hpp"

#include "cryptobase/Certificate.hpp"
#include "cryptobase/AttributeCertificate.hpp"
#include "cryptobase/AttributeCertificateReq.hpp"
#include "cryptobase/AttributeCertificateResp.hpp"
#include "cryptobase/AttributeCertificateSearchInfo.hpp"


#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>

#include <iostream>


using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using boost::shared_ptr;

namespace aafw {

ThriftServer::ThriftServer() :
		active_(false),
		aa_(dynamic_cast<AttributeAuthority&>(Poco::Util::Application::instance())),
		server_(nullptr),
		port_(9090)
{
}

ThriftServer::~ThriftServer()
{
}


aafw::AttributeCertificate ThriftServer::acToAc(const cryptobase::AttributeCertificate& ac)
{

	auto nameToName = [](const cryptobase::X509Name& name)
	{
		aafw::X509Name _name;
		for(auto entry : name.getEntries())
			_name[entry.first.getOidStr()] = entry.second;

		return _name;
	};

	auto info = ac.getInfo();
	aafw::ACInfo _info;
	aafw::ACHolder _holder;
	if(info.getHolder().getType() == cryptobase::Holder::HolderType::ENTITY_NAME)
	{
		auto name = info.getHolder().getHolderEntityName();
		_holder.__set_entityName(nameToName(name));
	}
	else if(info.getHolder().getType() == cryptobase::Holder::HolderType::BASE_CERT_ID)
	{
		auto issuerSerial = info.getHolder().getHolderBaseCertId();
		aafw::BaseCertId certId;
		certId.__set_issuer(nameToName(issuerSerial.getIssuer()));
		certId.__set_serial(issuerSerial.getSerialString());
		_holder.__set_baseCertId(certId);
	}
	_info.__set_issuer(nameToName(info.getIssuer()));
	_info.__set_version(info.getVersion());
	_info.__set_serial(info.getSerial());
	_info.__set_signatureAlgorithm(info.getSignature().getLongName());
	_info.__set_holder(_holder);
	aafw::ACValidity _validity;
	_validity.__set_notBeforeEpoch(info.getValidity().getNotBefore().getEpoch());
	_validity.__set_notAfterEpoch(info.getValidity().getNotAfter().getEpoch());
	_info.__set_validity(_validity);

	std::vector<aafw::Attribute> _attrs;
	for(auto attr : info.getAttributes())
	{
		aafw::Attribute _attr;
		_attr.__set_oid(attr.getOid().getOidStr());
		std::vector<std::string> _values;
		for(auto value : attr.getValues())
		{
			_values.push_back(std::string((const char *)value.begin(), value.size()));
		}
		_attr.__set_values(_values);

		_attrs.push_back(_attr);
	}
	_info.__set_attributes(_attrs);

	std::vector<aafw::Extension> _exts;
	for(auto ext : info.getExtensions())
	{
		aafw::Extension _ext;
		_ext.__set_oid(ext.getOid().getOidStr());
		_ext.__set_value(std::string((const char *)ext.getValue().begin(), ext.getValue().size()));

		_exts.push_back(_ext);
	}
	_info.__set_extensions(_exts);

	aafw::AttributeCertificate _ac;
	_ac.__set_algor(ac.getSignatureAlgorithm().getLongName());
	_ac.__set_signature(std::string((const char *)ac.getSignature().begin(), ac.getSignature().size()));
	_ac.__set_info(_info);
	_ac.__set_pem(ac.getPemEncoded());

	return _ac;
}

void ThriftServer::request(ACResp& _return, const ACReq& req)
{
	auto holderToHolder = [](const aafw::ACHolder& h)
		{
			cryptobase::X509Name entityName(X509_NAME_new());
			for (auto iter = h.entityName.begin(); iter != h.entityName.end(); ++iter)
				entityName.addEntry(cryptobase::ObjectIdentifier(iter->first), iter->second);

			cryptobase::X509Name issuer(X509_NAME_new());
			for (auto iter = h.baseCertId.issuer.begin(); iter != h.baseCertId.issuer.end(); ++iter)
				issuer.addEntry(cryptobase::ObjectIdentifier(iter->first), iter->second);

			if(h.__isset.entityName)
				return cryptobase::Holder(entityName);
			else
				return cryptobase::Holder(cryptobase::IssuerSerial(issuer, h.baseCertId.serial));
		};
	auto createErrorResp = [](aafw::ACFailureInfo::type failInfo, const std::string failText)
			{
				aafw::ACStatusInfo statusInfo;
				statusInfo.__set_status(aafw::ACStatus::type::rejection);
				statusInfo.__set_failInfo(failInfo);
				statusInfo.__set_failText(failText);

				return statusInfo;
			};

	std::unique_ptr<cryptobase::AttributeCertificateReq> r(nullptr);
	if(req.__isset.issueInfo)
	{
		if(!req.issueInfo.holder.__isset.entityName && !req.issueInfo.holder.__isset.baseCertId)
		{
			_return.__set_statusInfo(createErrorResp(aafw::ACFailureInfo::type::badRequest, "No Holder supplied (must supply entityName OR baseCertId)"));
			return;
		}
		cryptobase::Holder holder(holderToHolder(req.issueInfo.holder));
		cryptobase::AttributeCertificateIssueInfo issueInfo(holder);
		if(req.issueInfo.__isset.templateId)
		{
			issueInfo.setTemplateId(req.issueInfo.templateId);
		}
		if(req.issueInfo.__isset.attributes)
		{
			std::vector<cryptobase::Attribute> attrs;
			for(auto attr : req.issueInfo.attributes)
			{
				attrs.push_back(cryptobase::Attribute(cryptobase::ObjectIdentifier(attr.oid), attr.values));
			}


			issueInfo.setAttributes(attrs);
		}
		if(req.issueInfo.__isset.issuer)
		{
			cryptobase::X509Name issuer(X509_NAME_new());
			for (auto iter = req.issueInfo.issuer.begin(); iter != req.issueInfo.issuer.end(); ++iter)
				issuer.addEntry(cryptobase::ObjectIdentifier(iter->first), iter->second);

			issueInfo.setIssuer(issuer);
		}
		if(req.issueInfo.__isset.validity)
		{
			issueInfo.setValidity(cryptobase::AttributeCertificateValidity
					(cryptobase::GeneralizedTime(req.issueInfo.validity.notBeforeEpoch), cryptobase::GeneralizedTime(req.issueInfo.validity.notAfterEpoch)));
		}
		if(req.issueInfo.__isset.extensions)
		{
			std::vector<cryptobase::Extension> exts;
			for(auto attr : req.issueInfo.extensions)
				exts.push_back(cryptobase::Extension(cryptobase::ObjectIdentifier(attr.oid), attr.value, false));
			issueInfo.setExtensions(exts);
		}
		r.reset(new cryptobase::AttributeCertificateReq(issueInfo));
	}
	else if(req.__isset.searchInfo)
	{
		if(!req.searchInfo.holder.__isset.entityName && !req.searchInfo.holder.__isset.baseCertId)
		{
			_return.__set_statusInfo(createErrorResp(aafw::ACFailureInfo::type::badRequest, "No Holder supplied (must supply entityName OR baseCertId)"));
			return;
		}
		cryptobase::Holder holder(holderToHolder(req.searchInfo.holder));
		cryptobase::AttributeCertificateSearchInfo searchInfo(holder);
		if(req.searchInfo.__isset.attributesOid)
		{
			std::vector<cryptobase::ObjectIdentifier> oids;
			for(auto oid : req.searchInfo.attributesOid)
				oids.push_back(cryptobase::ObjectIdentifier(oid));

			searchInfo.setAttributesOid(oids);
		}
		r.reset(new cryptobase::AttributeCertificateReq(searchInfo));
	}
	else if(req.__isset.revInfo)
	{
		r.reset(new cryptobase::AttributeCertificateReq(req.revInfo));
	}
	else
	{
		_return.__set_statusInfo(createErrorResp(aafw::ACFailureInfo::type::badRequest, "You must supply issueInfo, revInfo or searchInfo"));
		return;
	}
	cryptobase::AttributeCertificateResp resp = aa_.handleRequest(*r.get());

	if(resp.granted())
	{
		aafw::ACStatusInfo statusInfo;
		statusInfo.__set_status(aafw::ACStatus::type::granted);
		_return.__set_statusInfo(statusInfo);

		std::vector<aafw::AttributeCertificate> acs;
		for(auto ac : resp.getAcs())
			acs.push_back(acToAc(ac));
		_return.__set_acs(acs);
	}
	else
	{
		_return.__set_statusInfo(createErrorResp((aafw::ACFailureInfo::type)resp.getStatusInfo().getFailInfo(), resp.getStatusInfo().getText()));
	}
}

void ThriftServer::stop()
{
	if(server_ != nullptr)
		server_->stop();

	if(serverThread_.joinable())
		serverThread_.join();

	server_.reset(nullptr);
	active_ = false;
}

void ThriftServer::start()
{
	#ifdef _WIN32
		WSADATA wsaData = {};
		WORD wVersionRequested = MAKEWORD(2, 2);
		WSAStartup(wVersionRequested, &wsaData); 
	#endif

	shared_ptr<ThriftServer> handler(new ThriftServer());
	shared_ptr<TProcessor> processor(new AAServiceProcessor(handler));
	shared_ptr<TServerTransport> serverTransport(new TServerSocket(port_));
	shared_ptr<TTransportFactory> transportFactory(new TBufferedTransportFactory());
	shared_ptr<TProtocolFactory> protocolFactory(new TBinaryProtocolFactory());

	server_.reset(new TSimpleServer(processor, serverTransport, transportFactory, protocolFactory));
	serverThread_ = std::thread(&TSimpleServer::serve, server_.get());
	active_ = true;
}

void ThriftServer::restart()
{
	stop();
	start();
}

bool ThriftServer::isActive()
{
	return active_;
}

std::string ThriftServer::getProtocolName()
{
	return "THRIFT";
}

} /* namespace aafw */
