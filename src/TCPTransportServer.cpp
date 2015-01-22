/*
 * TCPTransportServer.cpp
 *
 *  Created on: 14/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/TCPTransportServer.hpp"
#include "aafw/TcpProtocol.hpp"
#include "aafw/AttributeAuthority.hpp"

#include <iostream>

#include <chrono>
#include <thread>

namespace aafw {

TCPRequestConnection::TCPRequestConnection(const Poco::Net::StreamSocket& s) :
		Poco::Net::TCPServerConnection(s)
{
}

void TCPRequestConnection::run()
{
	std::cout << "Conexao de " << socket().peerAddress().toString() << std::endl;
	AttributeAuthority& aa = dynamic_cast<AttributeAuthority&>(Poco::Util::Application::instance()); // may throw std::bad_cast
	try
	{
		TcpProtocol::ProtocolContent content = TcpProtocol::read(socket());
		cryptobase::AttributeCertificateReq req(content.bytes);
		cryptobase::AttributeCertificateResp resp = aa.handleRequest(req);
		TcpProtocol::send(socket(), resp.getDerEncoded());
	}catch(const std::exception& ex){
		aa.handleTransportError(ex);
	}catch(...){
		aa.handleTransportError(cryptobase::Exception("Unknown error"));
	}
}

TCPTransportServer::TCPTransportServer(int port) :
		active_(false),
		port_(port),
		server_(nullptr)
{
}


TCPTransportServer::~TCPTransportServer()
{
	stop();
}

void TCPTransportServer::stop()
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

void TCPTransportServer::start()
{
	Poco::Net::ServerSocket svs(port_);
	server_.reset(new Poco::Net::TCPServer(new Poco::Net::TCPServerConnectionFactoryImpl<TCPRequestConnection>(), svs));
	svs.setReuseAddress(true);
	server_->start();
	active_ = true;
}

} /* namespace aafw */
