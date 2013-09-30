/*
 * UnRequestHandler.cxx
 *
 *  Created on: Sep 27, 2013
 *      Author: dzhukov
 */

#include <rutil/Logger.hxx>

#include "ReTurnSubsystem.hxx"
#include "UnRequestHandler.hxx"

#define RESIPROCATE_SUBSYSTEM ReTurnSubsystem::RETURN

using namespace resip;

namespace reTurn {

UnRequestHandler::UnRequestHandler(TurnManager& turnManager, const char *publicKeyPath,
                               const asio::ip::address* prim3489Address, unsigned short* prim3489Port,
                               const asio::ip::address* alt3489Address, unsigned short* alt3489Port)
	: RequestHandler(turnManager, prim3489Address, prim3489Port, alt3489Address, alt3489Port)
{
	int ret;
	if ((ret = uauth_new(&mUauth)) != UAUTH_OK) {
		CritLog(<< "Error creating uauth context. Error: " << ret);
		assert(0);
		return;
	}
	if ((ret = uauth_init(mUauth, publicKeyPath, NULL)) != UAUTH_OK) {
		CritLog(<< "Error initializing uauth context. Error: " << ret);
		assert(0);
		return;
	}
}

UnRequestHandler::~UnRequestHandler()
{
	int ret;
	if ((ret = uauth_delete(mUauth)) != UAUTH_OK) {
		CritLog(<< "Error destroying uauth context. Error: " << ret);
		assert(0);
		return;
	}
}

bool UnRequestHandler::handleAuthenticationWithMI(StunMessage& request,
		StunMessage& response)
{
	StackLog(<< "Validating username: " << *request.mUsername); // Note: we ensure username is present above

	Data::size_type splitSignPos = request.mUsername->find("=");
	if (splitSignPos == Data::npos) {
		WarningLog(<< "Username is not a Unison combined cookie");
		buildErrorResponse(response, 401, "Unauthorized", getConfig().mAuthenticationRealm.c_str());
		return false;
	}

	Data unSsData = request.mUsername->substr(0, splitSignPos);
	if (splitSignPos == 0) {
		WarningLog(<< "Username cookie does not contain un-ss-data cookie");
		buildErrorResponse(response, 401, "Unauthorized", getConfig().mAuthenticationRealm.c_str());
		return false;
	}
	if (splitSignPos >= request.mUsername->size() - 1) {
		WarningLog(<< "Username cookie does not contain un-ss-sign cookie");
		buildErrorResponse(response, 401, "Unauthorized", getConfig().mAuthenticationRealm.c_str());
		return false;
	}

	Data unSsSign = request.mUsername->substr(splitSignPos + 1, request.mUsername->size() - splitSignPos - 1);

	StackLog(<< "un-ss-data: " << unSsData);
	StackLog(<< "un-ss-sign: " << unSsSign);

	int ret;
	if ((ret = uauth_verify(mUauth, unSsData.c_str(), unSsSign.c_str())) != UAUTH_OK)
	{
		WarningLog(<< "Signature verification failed with error code " << ret);
		buildErrorResponse(response, 401, "Unauthorized", getConfig().mAuthenticationRealm.c_str());
		return false;
	}

	StackLog(<< "Signature verification succeeded");

	StackLog(<< "Validating MessageIntegrity");

	// Need to calculate HMAC across entire message - for LongTermAuthentication we use
	// username:realm:password string as the key
	Data hmacKey;
	assert(request.mHasUsername);  // Note:  This is checked above

	request.calculateHmacKey(hmacKey, "0");

	if (!request.checkMessageIntegrity(hmacKey)) {
		WarningLog(<< "MessageIntegrity is bad. Sending 401. Sender=" << request.mRemoteTuple);
		buildErrorResponse(response, 401, "Unauthorized",
				getConfig().mAuthenticationRealm.c_str());
		return false;
	}

	// need to compute this later after message is filled in
	response.mHasMessageIntegrity = true;
	response.mHmacKey = hmacKey; // Used to later calculate Message Integrity during encoding

	return true;
}

}

