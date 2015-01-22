
#include "aafw/DefaultFactory.hpp"
#include "aafw/FileSystemACStore.hpp"
#include "aafw/FileSystemACSerialLoader.hpp"
#include "aafw/CompositeTransportServer.hpp"
#include "aafw/TCPTransportServer.hpp"
#include "aafw/ThriftServer.hpp"
#include "aafw/NoCRLPublisher.hpp"
#include "aafw/FileSystemKeyLoader.hpp"

#include "Poco/Path.h"
#include "Poco/File.h"

namespace aafw {

std::unique_ptr<ACStore> DefaultFactory::getACStore() const
{
	return std::unique_ptr<ACStore>(new FileSystemACStore(Poco::Path::current(), cryptobase::EncodingType::DER));
}

std::unique_ptr<KeyLoader> DefaultFactory::getKeyLoader() const
{
	static const std::string PRIV_KEY_LOC(Poco::Path::current()+"privKey");
	static const std::string CERT_LOC(Poco::Path::current()+"cert");

	Poco::File f(PRIV_KEY_LOC);
	if(!f.exists())
	{
		EVP_PKEY * pkey = EVP_PKEY_new();
		RSA * rsa = RSA_generate_key(
			2048,   /* number of bits for the key - 2048 is a sensible value */
			RSA_F4, /* exponent - RSA_F4 is defined as 0x10001L */
			NULL,   /* callback - can be NULL if we aren't displaying progress */
			NULL    /* callback argument - not needed in this case */
		);
		EVP_PKEY_assign_RSA(pkey, rsa);

		X509 * x509 = X509_new();
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		X509_gmtime_adj(X509_get_notBefore(x509), 0);
		X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
		X509_set_pubkey(x509, pkey);

		X509_NAME * name = X509_get_subject_name(x509);
		X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                           (unsigned char *)"BR", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                           (unsigned char *)"AAFW", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                           (unsigned char *)"AAFW SELF-SIGNED", -1, -1, 0);
		X509_set_issuer_name(x509, name);
		X509_sign(x509, pkey, EVP_sha1());

		cryptobase::PrivateKey privKey(pkey);
		std::ofstream os(PRIV_KEY_LOC.c_str());
		os << privKey.getPemEncoded();
		os.close();

		cryptobase::Certificate cert(x509);
		std::ofstream osCert(CERT_LOC.c_str());
		osCert << cert.getPemEncoded();
		osCert.close();
	}

	return std::unique_ptr<KeyLoader>(new FileSystemKeyLoader(cryptobase::DigestAlg::SHA256,
	CERT_LOC, PRIV_KEY_LOC, ""));
}

std::unique_ptr<ACSerialLoader> DefaultFactory::getACSerialLoader() const
{
	return std::unique_ptr<ACSerialLoader>(new FileSystemACSerialLoader(Poco::Path::current()+"serial_ac.txt"));
}
std::unique_ptr<TransportServer> DefaultFactory::getTransportServer() const
{
	CompositeTransportServer *composite = new CompositeTransportServer();
	composite->add(std::unique_ptr<TransportServer>(new TCPTransportServer(50005)));
	composite->add(std::unique_ptr<TransportServer>(new ThriftServer()));
	return std::unique_ptr<TransportServer>(composite);
}

}