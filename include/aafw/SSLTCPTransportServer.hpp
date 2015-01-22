/*
 * SSLTCPTransportServer.hpp
 *
 *  Created on: 21/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef SSLTCPTRANSPORTSERVER_HPP_
#define SSLTCPTRANSPORTSERVER_HPP_

#include "aafw/Defs.h"
#include "aafw/TCPTransportServer.hpp"

#include "cryptobase/Certificate.hpp"
#include "cryptobase/PrivateKey.hpp"

namespace aafw {

class AAFW_API SSLTCPTransportServer: public TCPTransportServer
{
public:
	SSLTCPTransportServer(int port, const std::vector<cryptobase::Certificate>& trustedCerts, const cryptobase::Certificate& serverCert, const std::string& pemSslPrivKey, const std::string& passphrase = "");
	virtual ~SSLTCPTransportServer();

	void start();
private:
	std::vector<cryptobase::Certificate> trustedCerts_;
	cryptobase::Certificate serverCert_;
	cryptobase::PrivateKey privKey_;
};

} /* namespace aafw */
#endif /* SSLTCPTRANSPORTSERVER_HPP_ */
