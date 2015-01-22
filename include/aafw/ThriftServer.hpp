/*
 * ThriftServer.hpp
 *
 *  Criado em: 09/04/2014
 *      Autor: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#ifndef THRIFTSERVER_HPP_
#define THRIFTSERVER_HPP_

#include "aafw/AAService.h"
#include "aafw/TransportServer.hpp"
#include "aafw/Defs.h"

#include <thread>

namespace apache { namespace thrift { namespace server {
	class TSimpleServer;
} } }

namespace cryptobase {
	class AttributeCertificate;
}

namespace aafw {

class AttributeAuthority;

class AAFW_API ThriftServer : public AAServiceIf, public TransportServer {
public:
	ThriftServer();
	virtual ~ThriftServer();

	void request(ACResp& _return, const ACReq& req);

	void stop();
	void start();
	void restart();
	bool isActive();
	std::string getProtocolName();

	void setPort(int port);
	int getPort() const;
private:
	bool active_;
	AttributeAuthority& aa_;
	std::unique_ptr<apache::thrift::server::TSimpleServer> server_;
	int port_;
	std::thread serverThread_;

	aafw::AttributeCertificate acToAc(const cryptobase::AttributeCertificate& ac);
};

inline void ThriftServer::setPort(int port)
{
	port_ = port;
}

inline int ThriftServer::getPort() const
{
	return port_;
}

} /* namespace aafw */
#endif /* THRIFTSERVER_HPP_ */
