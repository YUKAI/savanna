#pragma once

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <functional>
#include <memory>
#include <mutex>

#include "endpoint.hpp"
#include "request.hpp"
#include "result.hpp"
#include "url.hpp"
#include "util.hpp"


namespace m2d
{
namespace savanna
{
namespace ssl_reuse
{
	namespace beast = boost::beast;
	namespace http = beast::http;
	namespace net = boost::asio;
	namespace ssl = net::ssl;
	using tcp = net::ip::tcp;

	template <class Body>
	class delegate{
	public:
		virtual bool completion_callback(savanna::result<http::response<Body>>) = 0;
	};
	class interface: public std::enable_shared_from_this<interface>{
	protected:
		virtual void on_resolve_l(beast::error_code ec, tcp::resolver::results_type) = 0;
		virtual void on_connect_l(beast::error_code ec, tcp::resolver::results_type::endpoint_type) = 0;
		virtual void on_handshake_l(beast::error_code ec) = 0;
		virtual void on_write_l(beast::error_code ec, std::size_t bytes_transferred) = 0;
		virtual void on_read_l(beast::error_code ec, std::size_t bytes_transferred) = 0;
		virtual void on_shutdown_l(beast::error_code ec) = 0;
	public:
		virtual ~interface()= default;
		virtual void error_callback(beast::error_code ec) = 0;
		void on_resolve(beast::error_code ec, tcp::resolver::results_type results){
			if (ec) {
				error_callback(ec);
				return;
			}
			on_resolve_l(ec, std::move(results));
		}
		void on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type type){
			if (ec) {
				error_callback(ec);
				return;
			}
			on_connect_l(ec, std::move(type));
		}
		void on_handshake(beast::error_code ec){
			if (ec) {
				error_callback(ec);
				return;
			}
			on_handshake_l(ec);
		}
		void on_write(beast::error_code ec, std::size_t bytes_transferred){
			boost::ignore_unused(bytes_transferred);
			if (ec) {
				error_callback(ec);
				return;
			}
			on_write_l(ec, bytes_transferred);
		}
		void on_read(beast::error_code ec, std::size_t bytes_transferred){
			boost::ignore_unused(bytes_transferred);
			if (ec) {
				error_callback(ec);
				return;
			}
			on_read_l(ec, bytes_transferred);
		}
		void on_shutdown(beast::error_code ec){
			if (ec == net::error::eof || ec == net::ssl::error::stream_truncated) {
				// Rationale:
				// http://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
				ec = {};
			}
			if (ec) {
				error_callback(ec);
				return;
			}
			on_shutdown_l(ec);
		}
		virtual void run(std::string host, std::string port_str, http::request<http::string_body> request) = 0;
		virtual void cancel() = 0;
	};
	template <class Body>
	class http_logic: public interface{
		delegate<Body>* delegate_;
		std::shared_ptr<beast::tcp_stream> tcp_stream_;
		std::shared_ptr<tcp::resolver> resolver_;
		std::chrono::nanoseconds timeout_interval_;
		beast::flat_buffer buffer_;
		http::response<Body> response_;
		http::request<http::string_body> request_;
		// Set right before the request starts to be written (see result::request_sent).
		bool request_written_ = false;
	protected:
		void error_callback(beast::error_code ec) override {
			savanna::result<http::response<Body>> result(beast::system_error { ec });
			result.request_sent = request_written_;
			if(delegate_) delegate_->completion_callback(std::move(result));
		}
		void on_resolve_l(beast::error_code ec, tcp::resolver::results_type results) override {
			tcp_stream_->expires_after(timeout_interval_);
			tcp_stream_->async_connect(results, beast::bind_front_handler(&http_logic<Body>::on_connect, this->shared_from_this()));
		}

		void on_connect_l(beast::error_code ec, tcp::resolver::results_type::endpoint_type) override {
			tcp_stream_->expires_after(timeout_interval_);
			request_written_ = true;
			http::async_write(*tcp_stream_, request_, beast::bind_front_handler(&http_logic<Body>::on_write, this->shared_from_this()));
		}
		void on_handshake_l(beast::error_code ec) override { }

		void on_write_l(beast::error_code ec, std::size_t bytes_transferred) override {
			http::async_read(*tcp_stream_, buffer_, response_, beast::bind_front_handler(&http_logic<Body>::on_read, this->shared_from_this()));
		}
		void on_read_l(beast::error_code ec, std::size_t bytes_transferred) override {
			if (ec && ec != beast::errc::not_connected) {
				error_callback(ec);
			}
			tcp_stream_->socket().shutdown(tcp::socket::shutdown_both, ec);
			if (ec && ec != beast::errc::not_connected) {
				error_callback(ec);
			}else {
				savanna::result<http::response<Body>> result(std::move(response_));
				result.request_sent = true;
				if(delegate_) delegate_->completion_callback(std::move(result));
			}
		}

		void on_shutdown_l(beast::error_code ec) override {}
	public:
		virtual ~http_logic() override{
			tcp_stream_ = nullptr;
			resolver_ = nullptr;
		}
		http_logic(std::shared_ptr<beast::tcp_stream> tcp_stream, std::shared_ptr<tcp::resolver> resolver, delegate<Body>* delegate, std::chrono::nanoseconds timeout_interval){
			resolver_ = resolver;
			tcp_stream_ = tcp_stream;
			delegate_ = delegate;
			timeout_interval_ = timeout_interval;
		}
		void run(std::string host, std::string port_str, http::request<http::string_body> request) override {
			request_ = request;
			resolver_->async_resolve(host, port_str, beast::bind_front_handler(&interface::on_resolve, this->shared_from_this()));
		}
		void cancel() override {
			tcp_stream_->cancel();
		};
	};
	template <class Body>
	class https_logic: public interface{
		delegate<Body>* delegate_;
		std::shared_ptr<beast::ssl_stream<beast::tcp_stream>> ssl_stream_;
		std::shared_ptr<tcp::resolver> resolver_;
		std::chrono::nanoseconds timeout_interval_;
		beast::flat_buffer buffer_;
		http::response<Body> response_;
		http::request<http::string_body> request_;
		std::string host_;
		std::map<std::string, std::shared_ptr<SSL_SESSION>>* ssl_cache_;
		std::string ipaddress_;
		// Set once the result of the request has been handed to the delegate. After that
		// only the TLS close (close_notify) is left, and it is not part of the result.
		bool delivered_ = false;
		// Set right before the request starts to be written (see result::request_sent).
		bool request_written_ = false;
		// How long to wait for the peer's close_notify after the response. Nothing needs
		// it, but run() does not return until the shutdown ends. (A function rather than a
		// static constexpr member, so C++11/14 users need no out-of-class definition.)
		static std::chrono::seconds shutdown_timeout() { return std::chrono::seconds(1); }
	protected:
		void error_callback(beast::error_code ec) override {
			// An error while closing the TLS session after the result was delivered (peer
			// reset, shutdown timeout) must not reach the delegate as a second completion.
			if (delivered_) {
				return;
			}
			savanna::result<http::response<Body>> result(beast::system_error { ec });
			result.request_sent = request_written_;
			if(delegate_) delegate_->completion_callback(std::move(result));
		}
		void on_resolve_l(beast::error_code ec, tcp::resolver::results_type results) override {
			if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(), host_.c_str())) {
				beast::error_code ssl_ec { static_cast<int>(::ERR_get_error()), net::error::get_ssl_category() };
				error_callback(ssl_ec);
				return;
			}
			// Set a timeout on the operation
			beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_interval_);
			// Make the connection on the IP address we get from a lookup
			beast::get_lowest_layer(*ssl_stream_).async_connect(results, beast::bind_front_handler(&https_logic<Body>::on_connect, this->shared_from_this()));
		}

		void on_connect_l(beast::error_code ec, tcp::resolver::results_type::endpoint_type type) override {
			// add session to the cache after a successful connection
			ipaddress_ = type.address().to_string();
			if(ssl_cache_) {
				auto cached_session = ssl_cache_->find(ipaddress_);
				if (cached_session != ssl_cache_->end()) {
					SSL_set_session(ssl_stream_->native_handle(), cached_session->second.get());
				}
			}

			ssl_stream_->async_handshake(
				ssl::stream_base::client,
				beast::bind_front_handler(
					&https_logic<Body>::on_handshake,
					this->shared_from_this()));
		}
		void on_handshake_l(beast::error_code ec) override {
			// after a connection can check if ssl-session was reused
			if(ssl_cache_) {
				auto session = std::shared_ptr<SSL_SESSION>(SSL_get1_session(ssl_stream_->native_handle()), SSL_SESSION_free);
				if (SSL_session_reused(ssl_stream_->native_handle())) {
				//	std::cout << "session reused" << std::endl;
				}
				else {
				//	std::cout << "session new negotiated" << std::endl;
					(*ssl_cache_)[ipaddress_] = session;
				}
			}
			// Set a timeout on the operation
			beast::get_lowest_layer(*ssl_stream_).expires_after(timeout_interval_);
			// Send the HTTP request to the remote host
			request_written_ = true;
			http::async_write(*ssl_stream_, request_, beast::bind_front_handler(&https_logic<Body>::on_write, this->shared_from_this()));
		}

		void on_write_l(beast::error_code ec, std::size_t bytes_transferred) override {
			http::async_read(*ssl_stream_, buffer_, response_, beast::bind_front_handler(&https_logic<Body>::on_read, this->shared_from_this()));
		}
		void on_read_l(beast::error_code ec, std::size_t bytes_transferred) override {
			bool unfollow = true;
			if (ec && ec != beast::errc::not_connected) {
				error_callback(ec);
			}
			else {
				savanna::result<http::response<Body>> result(std::move(response_));
				result.request_sent = true;
				if(delegate_) unfollow = delegate_->completion_callback(std::move(result));
			}
			if(unfollow){
				delivered_ = true;
				// The deadline set before the request is still running; without a new one a
				// peer that neither answers close_notify nor closes the connection keeps run()
				// blocked until the request timeout. close_notify is still sent first, so the
				// session stays resumable.
				beast::get_lowest_layer(*ssl_stream_).expires_after(shutdown_timeout());
				ssl_stream_->async_shutdown(beast::bind_front_handler(&https_logic<Body>::on_shutdown,this->shared_from_this()));
			}
		}

		void on_shutdown_l(beast::error_code ec) override {

		}
	public:
		https_logic(std::shared_ptr<beast::ssl_stream<beast::tcp_stream>> ssl_stream, std::shared_ptr<tcp::resolver> resolver, delegate<Body>* delegate, std::map<std::string, std::shared_ptr<SSL_SESSION>>* ssl_cache, std::chrono::nanoseconds timeout_interval){
			resolver_ = resolver;
			ssl_stream_ = ssl_stream;
			delegate_ = delegate;
			ssl_cache_ = ssl_cache;
			timeout_interval_ = timeout_interval;
		}
		void run(std::string host, std::string port_str, http::request<http::string_body> request) override {
			host_ = host;
			request_ = request;
			resolver_->async_resolve(host, port_str, beast::bind_front_handler(&interface::on_resolve, this->shared_from_this()));
		}
		void cancel() override {
			beast::get_lowest_layer(*ssl_stream_).cancel();
		};
	};
	template <class Body>
	class reuse_async_request_executor : public delegate<Body>{
	private:
		// need some object that will store the cache
		std::map<std::string, std::shared_ptr<SSL_SESSION>>* ssl_cache_;

		ssl::context ssl_ctx_;
		std::shared_ptr<interface> logic = nullptr;
		std::shared_ptr<http_logic<Body>> http_logic_ = nullptr;
		std::shared_ptr<https_logic<Body>> https_logic_ = nullptr;
		std::function<void(savanna::result<http::response<Body>>)> completion_ = nullptr;
		http::request<http::string_body> request_;
		savanna::ssl_reuse::request original_request_;
		std::shared_ptr<net::io_context> ctx_;
		std::shared_ptr<tcp::resolver> resolver_;
		std::shared_ptr<beast::tcp_stream> tcp_stream_;
		std::shared_ptr<beast::ssl_stream<beast::tcp_stream>> ssl_stream_;
		bool isReady_ = true;

		bool follow_location_ = false;
		// A redirect was followed: the original request already reached a server, so any
		// later result counts as sent even if the next leg fails before writing.
		bool redirected_ = false;

		std::string current_scheme()
		{
			auto target = request_.target();
			auto url = savanna::url(std::string(target));
			return url.scheme();
		}

		void update_request(const savanna::ssl_reuse::request& original_request, const std::string& new_target, const std::string& new_host)
		{
			request_.target(new_target);
			request_.set(http::field::host, new_host);
			for (auto & header_field : original_request.header_fields) {
				request_.set(header_field.first, header_field.second);
			}
			if (original_request.endpoint->method() != http::verb::get) {
				if (original_request.endpoint->params()) {
					auto p = *original_request.endpoint->params();
					request_.body() = original_request.body + savanna::param_str(p);
					request_.prepare_payload();
				}
				else {
					request_.body() = original_request.body;
					request_.prepare_payload();
				}
			}
			follow_location_ = original_request.follow_location;
		}

		void run(std::string host, std::string port_str)
		{
			select();
			logic->run(std::move(host), std::move(port_str), request_);
		}
		void select(){
			if (current_scheme() == url_scheme::https) {
				logic = https_logic_;
			}else{
				logic = http_logic_;
			}
		};

		bool completion_callback(savanna::result<http::response<http::dynamic_body>> result) override {
			if (redirected_) {
				result.request_sent = true;
			}
			if (!result.error) {
				if ((result.response->result_int() >= 300) && result.response->result_int() < 400 && follow_location_) {
					redirected_ = true;
					auto location = result.response->base()["Location"].to_string();
					auto new_url = savanna::url(location);
					update_request(original_request_, new_url.to_string(), new_url.host());
					run(new_url.host(), new_url.port_str());
					return false;
				}
			}
			completion_(result);
			return true;
		}
	public:
		reuse_async_request_executor (ssl::context ssl_ctx, std::map<std::string, std::shared_ptr<SSL_SESSION>>* ssl_cache)  : ssl_ctx_(std::move(ssl_ctx))
		{
			ssl_cache_ = ssl_cache;
		}
		// The streams and the resolver are registered with ctx_'s reactor, and the
		// http/https logic objects keep their own references to the streams. With the
		// default member-wise destruction ctx_ (declared after the logic members) is
		// released first, so the io_context is freed while the streams are still alive,
		// and closing their sockets later touches the freed reactor (use-after-free).
		// Release everything that uses ctx_ first, then ctx_ itself.
		~reuse_async_request_executor()
		{
			logic = nullptr;
			http_logic_ = nullptr;
			https_logic_ = nullptr;
			ssl_stream_ = nullptr;
			tcp_stream_ = nullptr;
			resolver_ = nullptr;
			ctx_ = nullptr;
		}
		bool send(savanna::ssl_reuse::request original_request, std::function<void(savanna::result<http::response<Body>>)> completion)
		{
			if(isReady_) {
				isReady_ = false;
				ctx_ = std::make_shared<net::io_context>();
				resolver_ = std::make_shared<tcp::resolver>(*ctx_);
				tcp_stream_ = std::make_shared<beast::tcp_stream>(*ctx_);
				ssl_stream_ = std::make_shared<beast::ssl_stream<beast::tcp_stream>>(*ctx_, ssl_ctx_);
				http_logic_ = std::make_shared<http_logic<Body>>(tcp_stream_, resolver_, this, original_request.timeout_interval);
				https_logic_ = std::make_shared<https_logic<Body>>(ssl_stream_, resolver_, this, ssl_cache_, original_request.timeout_interval);
				completion_ = completion;
				request_.version(original_request.version);
				request_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
				request_.method(original_request.endpoint->method());
				original_request_ = original_request;
				update_request(original_request, original_request.endpoint->build_url_str(), original_request.endpoint->host());

				auto url = original_request.endpoint->url();
				run(url.host(), url.port_str());
				ctx_->run();
				return true;
			}
			return false;
		}
		void cancel()
		{
			if(logic) logic->cancel();
		}
	};

	class reuse_async_url_session
	{
	private:
		// need some object that will store the cache
		std::map<std::string, std::shared_ptr<SSL_SESSION>> ssl_cache_;
	public:
		explicit reuse_async_url_session()
		{
			ssl_cache_ = {};
		}
		virtual ~reuse_async_url_session(){ }

		template <class Body>
		std::shared_ptr<reuse_async_request_executor<Body>> prepare(ssl::context ssl_ctx){
			auto executor = std::make_shared<reuse_async_request_executor<Body>>(std::move(ssl_ctx), &ssl_cache_);
			return executor;
		}

		std::map<std::string, std::shared_ptr<SSL_SESSION>> ssl_cache(){
			return ssl_cache_;
		}
		void ssl_cache(std::map<std::string, std::shared_ptr<SSL_SESSION>> ssl_cache){
			ssl_cache_ = ssl_cache;
		}

	};
}
}
}