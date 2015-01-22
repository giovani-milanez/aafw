/*
 * TcpProtocol.cpp
 *
 *  Created on: 19/06/2013
 *      Author: Giovani Milanez Espindola
 *  giovani.milanez@gmail.com
 */

#include "aafw/TcpProtocol.hpp"

#include "Poco/Net/StreamSocket.h"
#include "Poco/ByteOrder.h"

namespace aafw {

CRYPTOBASE_IMPLEMENT_EXCEPTION(TcpProtocolException, cryptobase::Exception, "TCP Exception")
CRYPTOBASE_IMPLEMENT_EXCEPTION(TooLargeRequestException, TcpProtocolException, "Too Large Message")
CRYPTOBASE_IMPLEMENT_EXCEPTION(SendBytesException, TcpProtocolException, "Could not send message")
CRYPTOBASE_IMPLEMENT_EXCEPTION(ReceiveBytesException, TcpProtocolException, "Could not receive message")

TcpProtocol::ProtocolContent TcpProtocol::read(Poco::Net::StreamSocket& socket, bool flipBytes, int maxReqLen)
{
	ProtocolContent p;

	// Reading size of message
	p.size = *reinterpret_cast<Poco::UInt32 *>(readAll(socket, sizeof(Poco::UInt32)).begin());
	if(flipBytes)
		p.size = Poco::ByteOrder::flipBytes(p.size);

	if(p.size >= (unsigned int) maxReqLen)
		throw TooLargeRequestException("");

	// Reading flag
	p.flag = *static_cast<Poco::UInt8 *>(readAll(socket, sizeof(Poco::UInt8)).begin());

	// reading content
	p.bytes = readAll(socket, p.size - 1);

	return p;
}

void TcpProtocol::send(Poco::Net::StreamSocket& socket, const cryptobase::ByteArray& content, bool flipBytes)
{
	Poco::UInt8 flag = 5;
	Poco::UInt32 messageSize = sizeof(Poco::UInt8) + content.size();
	if (flipBytes)
		messageSize = Poco::ByteOrder::flipBytes(messageSize);
	sendAll(socket, &messageSize, sizeof(Poco::UInt32));
	sendAll(socket, &flag, sizeof(Poco::UInt8));
	sendAll(socket, content.begin(), content.size());
}

void TcpProtocol::sendAll(Poco::Net::StreamSocket& socket, const void *buffer, int size)
{
	int toSend = size;
	int sent = 0;
	int bytesleft = toSend;
	const char *b = reinterpret_cast<const char *>(buffer);
	do{
		int s = socket.sendBytes(b+sent, bytesleft);
		if(s <= 0)
			throw SendBytesException("");
		sent += s;
		bytesleft -= s;
	}while(sent != toSend);
}

cryptobase::ByteArray TcpProtocol::readAll(Poco::Net::StreamSocket& socket, int size)
{
	int toRead = size;
	cryptobase::ByteArray content(toRead);

	int bytesleft = toRead;
	int read = 0;
	do
	{
		int received = socket.receiveBytes(content.begin()+read, bytesleft);
		if (received == 0)
			throw ReceiveBytesException("Connection shutdown by peer");
		read += received;
		bytesleft -= received;
	}while(read != toRead);
	return content;
}


}

