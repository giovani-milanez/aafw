/*
 * HTTPTransportServer.cpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/HTTPTransportServer.hpp"
#include "aafw/AttributeAuthority.hpp"

#include "Poco/Net/HTTPRequestHandler.h"
#include "Poco/Net/HTTPServerRequest.h"
#include "Poco/Net/HTTPServerResponse.h"

#include <iostream>

#include <chrono>
#include <thread>

namespace aafw {

class HTTPErrorHandler : public Poco::Net::HTTPRequestHandler
{
public:
	void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response)
	{
		std::cout << "URI inválida" << std::endl;
	}
};


class HTTPRequestConnection : public Poco::Net::HTTPRequestHandler
{
public:
	void handleRequest(Poco::Net::HTTPServerRequest& request, Poco::Net::HTTPServerResponse& response)
	{
		std::cout << "Nova requisicao HTTP de " << request.clientAddress().host().toString() << std::endl;
		AttributeAuthority& aa = dynamic_cast<AttributeAuthority&>(Poco::Util::Application::instance()); // may throw std::bad_cast
		try
		{
			response.setContentType("pkix-attr-cert-resp");
	//		if(request.getContentType() != REQUEST_CONTENT_TYPE)
	//			throw Crypto::CryptoException(_fcore("##Content type '{1}' não é válido. Suportamos somente '{2}'.", % request.getContentType() % REQUEST_CONTENT_TYPE), WHERE, false);

	//		if(request.getContentLength() >= Rfc3161TcpProtocol::MAX_REQUEST_LENGTH)
	//			throw Crypto::Tsa::BadRequestException(_tcore("##O tamanho da mensagem HTTP é grande demais."), WHERE, false);

			cryptobase::ByteArray requestBa(request.getContentLength());
			request.stream().read((char *)requestBa.begin(), requestBa.size());

			cryptobase::AttributeCertificateReq req(requestBa);
			cryptobase::AttributeCertificateResp resp = aa.handleRequest(req);

			cryptobase::ByteArray responseBa = resp.getDerEncoded();
			response.setContentLength(responseBa.size());
			response.send() << responseBa;
		}catch(const std::exception& ex){
			aa.handleTransportError(ex);
		}catch(...){
			aa.handleTransportError(cryptobase::Exception("Unknown error"));
		}

	}
};

class HttpFactory : public Poco::Net::HTTPRequestHandlerFactory
{
public:
	HttpFactory(const std::string& uri) : uri_(uri) {}
	Poco::Net::HTTPRequestHandler* createRequestHandler(const Poco::Net::HTTPServerRequest& request)
	{
		if (request.getURI() == ("/"+uri_))
			return new HTTPRequestConnection;

		return new HTTPErrorHandler;
	}
private:
	std::string uri_;
};

HTTPTransportServer::HTTPTransportServer(int port, const std::string& uri) :
		active_(false),
		port_(port),
		uri_(uri),
		server_(nullptr)
{
}

HTTPTransportServer::~HTTPTransportServer()
{
}

void HTTPTransportServer::stop()
{
	if(active_)
	{
		server_->stop();
		while(server_->currentConnections() != 0)
			std::this_thread::sleep_for(std::chrono::microseconds(100000));
			//usleep(100000);
		active_ = false;
	}
}

void HTTPTransportServer::start()
{
	Poco::Net::ServerSocket svs(port_);
	int maxQueued = 100;
	int maxThreads = 16;

	Poco::Net::HTTPServerParams* pParams = new Poco::Net::HTTPServerParams;
	pParams->setMaxQueued(maxQueued);
	pParams->setMaxThreads(maxThreads);

	server_.reset(new Poco::Net::HTTPServer(new HttpFactory(uri_), svs, pParams));
	svs.setReuseAddress(true);
	server_->start();
	active_ = true;
}

} /* namespace aafw */
