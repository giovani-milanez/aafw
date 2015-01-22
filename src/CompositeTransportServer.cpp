#include "aafw/CompositeTransportServer.hpp"

namespace aafw {

void CompositeTransportServer::stop()
{
	for(auto& s : servers_)
		s->stop();
}

void CompositeTransportServer::start()
{
	for(auto& s : servers_)
		s->start();
}

void CompositeTransportServer::restart()
{
	for(auto& s : servers_)
		s->restart();
}

bool CompositeTransportServer::isActive()
{
	for(auto& s : servers_)
		if(!s->isActive())
			return false;

	return !servers_.empty();
}

std::string CompositeTransportServer::getProtocolName()
{
	if(servers_.empty())
		return "NONE";

	if(servers_.size() == 1)
		return servers_[0]->getProtocolName();

	std::string protocols;
	for(auto& s : servers_)
		protocols += s->getProtocolName()+", ";

	return protocols;
}

void CompositeTransportServer::add(std::unique_ptr<TransportServer> server)
{
	servers_.push_back(std::move(server));
}

}