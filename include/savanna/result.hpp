#pragma once

#include <boost/optional.hpp>

namespace m2d
{
namespace savanna
{
	template <typename Response>
	class result
	{
	public:
		boost::optional<Response> response;
		boost::optional<boost::system::system_error> error;
		// true once the request has started to be written to the server (or a redirect
		// was followed). When false, the error happened while resolving, connecting or
		// in the TLS handshake, so the server cannot have received the request and it is
		// safe to send it again even if it is not idempotent.
		bool request_sent = false;

		result(Response response)
		    : response(response)
		    , error(boost::none)
		{
		}

		result(boost::system::system_error error)
		    : response(boost::none)
		    , error(error)
		{
		}
	};
}
}
