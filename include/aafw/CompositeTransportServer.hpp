/*
 * CompositeTransportServer.hpp
 *
 *  Created on: 15/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef COMPOSITETRANSPORTSERVER_HPP_
#define COMPOSITETRANSPORTSERVER_HPP_

#include "aafw/Defs.h"

#include "aafw/TransportServer.hpp"

#include <vector>
#include <memory>

namespace aafw {

/**
 * Implements Composite pattern for TransportServer.
 * You can use this class to have multiples TransportServer running (eg. listening requests from TCP and HTTP)
 */
class AAFW_API CompositeTransportServer: public TransportServer
{
public:
	virtual ~CompositeTransportServer(){}

	/**
	 * Stops all the TransportServer registered by method add()
	 */
	void stop();
	/**
	 * Starts all the TransportServer registered by method add()
	 */
	void start();
	/**
	 * Restarts all the TransportServer registered by method add()
	 */
	void restart();
	/**
	 * Check if all the TransportServer registered by method add() are
	 * active. If none registered or one of them is not active it will return false.
	 */
	bool isActive();
	/**
	 * Return the protocol name separated with ',' of all registered TransportServer.
	 * If none registered NONE will be returned.
	 */
	std::string getProtocolName();

	/**
	 * Adds(register) an TransportServer to the list.
	 */
	void add(std::unique_ptr<TransportServer> server);
private:
	std::vector<std::unique_ptr<TransportServer>> servers_;
};

} /* namespace aafw */
#endif /* COMPOSITETRANSPORTSERVER_HPP_ */
