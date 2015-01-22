/*
 * TcpProtocol.hpp
 *
 *  Created on: 16/01/2014
 *      Author: Giovani Milanez Espindola
 *  Contact: giovani.milanez@gmail.com
 */

#ifndef TCPPROTOCOL_HPP_
#define TCPPROTOCOL_HPP_

#include "aafw/Defs.h"

#include "cryptobase/ByteArray.hpp"
#include "cryptobase/Exception.hpp"

#include "Poco/Types.h"

namespace Poco {
namespace Net {
	class StreamSocket;
}
}
namespace aafw {

CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, TcpProtocolException, cryptobase::Exception)
CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, TooLargeRequestException, TcpProtocolException)
CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, SendBytesException, TcpProtocolException)
CRYPTOBASE_DECLARE_EXCEPTION(AAFW_API, ReceiveBytesException, TcpProtocolException)

class AAFW_API TcpProtocol
{
public:
	typedef struct AAFW_API ProtocolContent_str
	{
		Poco::UInt32 size;
		Poco::UInt8 flag;
		cryptobase::ByteArray bytes;
		ProtocolContent_str() : size(0), flag(-1), bytes(0u)
		{
		}
		ProtocolContent_str(const ProtocolContent_str& src) :
			size(src.size),
			flag(src.flag),
			bytes(src.bytes)
		{
		}
		ProtocolContent_str& operator=(const ProtocolContent_str& rhs)
		{
			if (this != &rhs)
			{
				size = rhs.size;
				flag = rhs.size;
				bytes = rhs.bytes;
			}
			return *this;
		}
	} ProtocolContent;

	static const int MAX_REQUEST_LENGTH = 10241;
	static ProtocolContent read(Poco::Net::StreamSocket& socket, bool flipBytes = true, int maxReqLen = MAX_REQUEST_LENGTH);
	static void send(Poco::Net::StreamSocket& socket, const cryptobase::ByteArray& content, bool flipBytes = true);
private:
	static void sendAll(Poco::Net::StreamSocket& socket, const void *buffer, int size);
	static cryptobase::ByteArray readAll(Poco::Net::StreamSocket& socket, int size);

};

} /* namespace aafw */
#endif /* TCPPROTOCOL_HPP_ */
