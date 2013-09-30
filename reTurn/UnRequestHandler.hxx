/*
 * UnRequestHandler.hxx
 *
 *  Created on: Sep 27, 2013
 *      Author: dzhukov
 */

#ifndef UNREQUESTHANDLER_HXX_
#define UNREQUESTHANDLER_HXX_

extern "C" {
#include <uauth/uauth.h>
}

#include "RequestHandler.hxx"

namespace reTurn {

class UnRequestHandler : public RequestHandler
{
public:
	explicit UnRequestHandler(TurnManager& turnManager, const char *publicKeyPath,
						    const asio::ip::address* prim3489Address = 0, unsigned short* prim3489Port = 0,
						    const asio::ip::address* alt3489Address = 0, unsigned short* alt3489Port = 0);

	virtual ~UnRequestHandler();

protected:

   // Authentication handler
   virtual bool handleAuthenticationWithMI(StunMessage& request, StunMessage& response);

private:

   struct uauth_ctx *mUauth;

};

}


#endif /* UNREQUESTHANDLER_HXX_ */
