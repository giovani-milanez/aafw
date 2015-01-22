/*
 * TCPTransportServer.hpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef TCPTRANSPORTSERVER_HPP_
#define TCPTRANSPORTSERVER_HPP_

#include "aafw/Defs.h"
#include "aafw/TransportServer.hpp"

#include "Poco/Net/TCPServer.h"

#include <memory>

namespace aafw {

class AAFW_API TCPRequestConnection : public Poco::Net::TCPServerConnection
{
public:
	TCPRequestConnection(const Poco::Net::StreamSocket& s);
	void run();
};


class AAFW_API TCPTransportServer: public TransportServer
{
public:
	TCPTransportServer(int port);
	virtual ~TCPTransportServer();

	void stop();
	virtual void start();
	void restart();
	bool isActive();
	std::string getProtocolName();
protected:
	bool active_;
	int port_;
	std::unique_ptr<Poco::Net::TCPServer> server_;
};

inline void TCPTransportServer::restart()
{
	stop();
	start();
}

inline bool TCPTransportServer::isActive()
{
	return active_;
}

inline std::string TCPTransportServer::getProtocolName()
{
	return "TCP";
}

} /* namespace aafw */
#endif /* TCPTRANSPORTSERVER_HPP_ */
