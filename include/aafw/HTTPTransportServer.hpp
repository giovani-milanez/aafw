/*
 * HTTPTransportServer.hpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef HTTPTRANSPORTSERVER_HPP_
#define HTTPTRANSPORTSERVER_HPP_

#include "aafw/Defs.h"
#include "aafw/TransportServer.hpp"

#include "Poco/Net/HTTPServer.h"

#include <memory>

namespace aafw {

/**
 * @brief Implements an HTTP TransportServer
 * Implements an HTTP Server for listening Attribute Certificate Requests.
 * It is expected that the request content type to be DER encoded Attribute Certificate Request.
 * It will decode the request, forward to AttributeAuthority and return an Attribute Certificate Response
 * to the requester as DER encoded and pkix-attr-cert-resp content-type
 */

class AAFW_API HTTPTransportServer: public TransportServer
{
public:
	/**
	 * @param port The port HTTP Server will listen to
	 * @param uri The URI to listen for requests
	 */
	HTTPTransportServer(int port, const std::string& uri = "");
	virtual ~HTTPTransportServer();

	/**
	 * Stops the HTTP Server from listening
	 */
	void stop();
	/**
	 * Starts HTTP Server
	 */
	void start();
	/**
	 * Restarts HTTP Server
	 */
	void restart();
	/**
	 * Returns wheter the server is active (listening to requests)
	 */
	bool isActive();
	/**
	 * returns HTTP
	 */
	std::string getProtocolName();
private:
	bool active_;
	int port_;
	std::string uri_;
	std::unique_ptr<Poco::Net::HTTPServer> server_;
};

inline void HTTPTransportServer::restart()
{
	stop();
	start();
}

inline bool HTTPTransportServer::isActive()
{
	return active_;
}

inline std::string HTTPTransportServer::getProtocolName()
{
	return "HTTP";
}

} /* namespace aafw */
#endif /* HTTPTRANSPORTSERVER_HPP_ */
