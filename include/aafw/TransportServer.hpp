/*
 * TransportServer.hpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef TRANSPORTSERVER_HPP_
#define TRANSPORTSERVER_HPP_

#include <string>

namespace aafw {

/**
 * @brief An interface responsible for listening Attribute Certificate Requests
 * An interface responsible for listening Attribute Certificate Requests,
 * forward it to AttributeAuthority process and return the response to the requester.
 * See HTTPTransportServer.
 */

class TransportServer
{
public:
	TransportServer(){}
	virtual ~TransportServer(){}

	/**
	 * Stops the server from listening requests.
	 */
	virtual void stop() = 0;
	/**
	 * Starts the server and begin to listen requests
	 */
	virtual void start() = 0;
	/**
	 * Restarts the server
	 */
	virtual void restart() = 0;
	/**
	 * Returns if the server is active (that is, listening to requests)
	 */
	virtual bool isActive() = 0;
	/**
	 * Return the protocol used to receive request and send responses. (eg. HTTP, TCP...)
	 */
	virtual std::string getProtocolName() = 0;
private:
	TransportServer(const TransportServer&);
    TransportServer& operator=(const TransportServer&);
};

}

#endif /* TRANSPORTSERVER_HPP_ */
