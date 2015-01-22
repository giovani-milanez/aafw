
#ifndef AAFW_DEFAULT_FACTORY_HPP_
#define AAFW_DEFAULT_FACTORY_HPP_

#include "aafw/Defs.h"
#include "aafw/SystemFactory.hpp"

namespace aafw {

class AAFW_API DefaultFactory : public SystemFactory 
{
public:
	/**
	 * Uses FileSystemACStore implementation on current directory.
	 */
	std::unique_ptr<ACStore> getACStore() const;
	/**
	 * Uses FileSystemKeyLoader implementation. If its the first time (that is, if the private key was not generated yet),
	 * It will generate a private key and a self signed certificate and store both on current directory.
	 */
	std::unique_ptr<KeyLoader> getKeyLoader() const;
	/**
	 * Uses FileSystemACSerialLoader implementation on current directory.
	 */
	std::unique_ptr<ACSerialLoader> getACSerialLoader() const;
	/**
	 * Uses CompositeTransportServer implementation with TCPTransportServer (port 50005) and ThriftServer.
	 */
	std::unique_ptr<TransportServer> getTransportServer() const;
};

}

#endif