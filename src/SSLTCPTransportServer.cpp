/*
 * SSLTCPTransportServer.cpp
 *
 *  Created on: 21/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#include "aafw/SSLTCPTransportServer.hpp"

#include "Poco/Net/Context.h"
#include "Poco/Net/SecureServerSocket.h"

#include <sstream>

namespace aafw {

SSLTCPTransportServer::SSLTCPTransportServer(int port, const std::vector<cryptobase::Certificate>& trustedCerts,
		const cryptobase::Certificate& serverCert, const std::string& pemSslPrivKey, const std::string& passphrase) :
		TCPTransportServer(port),
		trustedCerts_(trustedCerts),
		serverCert_(serverCert),
		privKey_(pemSslPrivKey, passphrase)
{
}

SSLTCPTransportServer::~SSLTCPTransportServer()
{
}

void SSLTCPTransportServer::start()
{
	Poco::Net::Context::Ptr context(new Poco::Net::Context(
				Poco::Net::Context::SERVER_USE,
				"", // private key file
				"", // certificate file
				"", // ca location
				Poco::Net::Context::VERIFY_STRICT,
				9,
				false,
				"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH")
			);
	context->enableExtendedCertificateVerification(false);

	context->useCertificate(Poco::Crypto::X509Certificate(X509_dup(serverCert_.internal_)));

	std::istringstream issKey(privKey_.getPemEncoded());
	context->usePrivateKey(Poco::Crypto::RSAKey(nullptr, &issKey));

	X509_STORE *store = context->sslContext()->cert_store;
	for (auto& cert : trustedCerts_)
	{
		X509_STORE_add_cert(store, const_cast<X509 *>(cert.internal_));
	}

	Poco::Net::SecureServerSocket ssvs(port_, 64, context);
	server_.reset(new Poco::Net::TCPServer(new Poco::Net::TCPServerConnectionFactoryImpl<TCPRequestConnection>(), ssvs));
	ssvs.setReuseAddress(true);
	server_->start();
	active_ = true;
}

} /* namespace aafw */
