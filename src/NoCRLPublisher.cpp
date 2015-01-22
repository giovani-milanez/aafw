
#include "aafw/NoCRLPublisher.hpp"

namespace aafw {

void NoCRLPublisher::publish(const cryptobase::CertificateRevocationList& crl)
{
}
std::unique_ptr<cryptobase::CertificateRevocationList> NoCRLPublisher::get() const
{
	return std::unique_ptr<cryptobase::CertificateRevocationList>();
}

std::string NoCRLPublisher::getDistPointUrl() const
{
	return "";
}

}