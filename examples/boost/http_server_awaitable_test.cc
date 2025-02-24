//
// Copyright (c) 2022 Klemens D. Morgenstern (klemens dot morgenstern at gmx dot
// net)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Official repository: https://github.com/boostorg/beast
//

//------------------------------------------------------------------------------
//
// Example: HTTP server, coroutine
//
//------------------------------------------------------------------------------

#include <algorithm>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>
#include <cstdlib>
#include <fmt/core.h>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace http = beast::http;     // from <boost/beast/http.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

#include <boost/asio/experimental/awaitable_operators.hpp>
using namespace boost::asio::experimental::awaitable_operators;

void callback_add(int arg1, int arg2, std::move_only_function<void(int)> cb)
{
    std::thread([=, f = std::move(cb)]() mutable {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::move(f)(arg1 + arg2);
    }).detach();
}

template <typename Token> auto async_add(int arg1, int arg2, Token &&token)
{
    auto init = [](auto completion_handler, int arg1, int arg2) {
        callback_add(arg1, arg2, std::move(completion_handler));
    };

    return net::async_initiate<Token, void(int)>(init, token, arg1, arg2);
}

auto awaitable_add(int arg1, int arg2) -> boost::asio::awaitable<int>
{
    co_return co_await async_add(arg1, arg2, net::use_awaitable);
}

using tcp_stream = typename beast::tcp_stream::rebind_executor<
    net::use_awaitable_t<>::executor_with_default<net::any_io_executor>>::other;

// Return a reasonable mime type based on the extension of a file.
beast::string_view mime_type(beast::string_view path)
{
    using beast::iequals;
    auto const ext = [&path] {
        auto const pos = path.rfind(".");
        if (pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if (iequals(ext, ".htm"))
        return "text/html";
    if (iequals(ext, ".html"))
        return "text/html";
    if (iequals(ext, ".php"))
        return "text/html";
    if (iequals(ext, ".css"))
        return "text/css";
    if (iequals(ext, ".txt"))
        return "text/plain";
    if (iequals(ext, ".js"))
        return "application/javascript";
    if (iequals(ext, ".json"))
        return "application/json";
    if (iequals(ext, ".xml"))
        return "application/xml";
    if (iequals(ext, ".swf"))
        return "application/x-shockwave-flash";
    if (iequals(ext, ".flv"))
        return "video/x-flv";
    if (iequals(ext, ".png"))
        return "image/png";
    if (iequals(ext, ".jpe"))
        return "image/jpeg";
    if (iequals(ext, ".jpeg"))
        return "image/jpeg";
    if (iequals(ext, ".jpg"))
        return "image/jpeg";
    if (iequals(ext, ".gif"))
        return "image/gif";
    if (iequals(ext, ".bmp"))
        return "image/bmp";
    if (iequals(ext, ".ico"))
        return "image/vnd.microsoft.icon";
    if (iequals(ext, ".tiff"))
        return "image/tiff";
    if (iequals(ext, ".tif"))
        return "image/tiff";
    if (iequals(ext, ".svg"))
        return "image/svg+xml";
    if (iequals(ext, ".svgz"))
        return "image/svg+xml";
    return "application/text";
}

// Append an HTTP rel-path to a local filesystem path.
// The returned path is normalized for the platform.
std::string path_cat(beast::string_view base, beast::string_view path)
{
    if (base.empty())
        return std::string(path);
    std::string result(base);
#ifdef BOOST_MSVC
    char constexpr path_separator = '\\';
    if (result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
    for (auto &c : result)
        if (c == '/')
            c = path_separator;
#else
    char constexpr path_separator = '/';
    if (result.back() == path_separator)
        result.resize(result.size() - 1);
    result.append(path.data(), path.size());
#endif
    return result;
}

// Return a response for the given request.
//
// The concrete type of the response message (which depends on the
// request), is type-erased in message_generator.
template <class Body, class Allocator>
http::message_generator
handle_request(beast::string_view doc_root,
               http::request<Body, http::basic_fields<Allocator>> &&req)
{
    auto const dummy = [&req](beast::string_view target) {
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "The resource was dummy.";
        res.prepare_payload();
        return res;
    };
    // Returns a bad request response
    auto const bad_request = [&req](beast::string_view why) {
        http::response<http::string_body> res{http::status::bad_request,
                                              req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = std::string(why);
        res.prepare_payload();
        return res;
    };

    // Returns a not found response
    auto const not_found = [&req](beast::string_view target) {
        http::response<http::string_body> res{http::status::not_found,
                                              req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() =
            "The resource '" + std::string(target) + "' was not found.";
        res.prepare_payload();
        return res;
    };

    // Returns a server error response
    auto const server_error = [&req](beast::string_view what) {
        http::response<http::string_body> res{
            http::status::internal_server_error, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, "text/html");
        res.keep_alive(req.keep_alive());
        res.body() = "An error occurred: '" + std::string(what) + "'";
        res.prepare_payload();
        return res;
    };

    return dummy(req.target());

    // Make sure we can handle the method
    if (req.method() != http::verb::get && req.method() != http::verb::head)
        return bad_request("Unknown HTTP-method");

    // Request path must be absolute and not contain "..".
    if (req.target().empty() || req.target()[0] != '/' ||
        req.target().find("..") != beast::string_view::npos)
        return bad_request("Illegal request-target");

    // Build the path to the requested file
    std::string path = path_cat(doc_root, req.target());
    if (req.target().back() == '/')
        path.append("index.html");

    // Attempt to open the file
    beast::error_code ec;
    http::file_body::value_type body;
    body.open(path.c_str(), beast::file_mode::scan, ec);

    // Handle the case where the file doesn't exist
    if (ec == beast::errc::no_such_file_or_directory)
        // return not_found(req.target());
        return dummy(req.target());

    // Handle an unknown error
    if (ec)
        return server_error(ec.message());

    // Cache the size since we need it after the move
    auto const size = body.size();

    // Respond to HEAD request
    if (req.method() == http::verb::head) {
        http::response<http::empty_body> res{http::status::ok, req.version()};
        res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
        res.set(http::field::content_type, mime_type(path));
        res.content_length(size);
        res.keep_alive(req.keep_alive());
        return res;
    }

    // Respond to GET request
    http::response<http::file_body> res{
        std::piecewise_construct, std::make_tuple(std::move(body)),
        std::make_tuple(http::status::ok, req.version())};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, mime_type(path));
    res.content_length(size);
    res.keep_alive(req.keep_alive());
    return res;
}

//------------------------------------------------------------------------------

// Handles an HTTP server connection
net::awaitable<void> do_session(tcp_stream stream,
                                std::shared_ptr<std::string const> doc_root)
{
    // This buffer is required to persist across reads
    beast::flat_buffer buffer;

    // This lambda is used to send messages
    try {
        for (;;) {
            // Set the timeout.
            stream.expires_after(std::chrono::seconds(30));

            // Read a request
            http::request<http::string_body> req;
            co_await http::async_read(stream, buffer, req);

            // Handle the request
            http::message_generator msg =
                handle_request(*doc_root, std::move(req));

            // auto foo = co_await (awaitable_add(1, 2));
            // auto foo = co_await (awaitable_add(1, 2) && awaitable_add(1, 2));
            // fmt::print("Result: {}\n", foo);

            // Determine if we should close the connection
            bool keep_alive = msg.keep_alive();

            // Send the response
            co_await beast::async_write(stream, std::move(msg),
                                        net::use_awaitable);

            if (!keep_alive) {
                // This means we should close the connection, usually because
                // the response indicated the "Connection: close" semantic.
                break;
            }
        }
    } catch (boost::system::system_error &se) {
        if (se.code() != http::error::end_of_stream)
            throw;
    }

    // Send a TCP shutdown
    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_send, ec);

    // At this point the connection is closed gracefully
    // we ignore the error because the client might have
    // dropped the connection already.
}

//------------------------------------------------------------------------------

// Accepts incoming connections and launches the sessions
net::awaitable<void> do_listen(tcp::endpoint endpoint,
                               std::shared_ptr<std::string const> doc_root)
{
    // Open the acceptor
    auto acceptor = net::use_awaitable.as_default_on(
        tcp::acceptor(co_await net::this_coro::executor));
    acceptor.open(endpoint.protocol());

    // Allow address reuse
    acceptor.set_option(net::socket_base::reuse_address(true));

    // Bind to the server address
    acceptor.bind(endpoint);

    // Start listening for connections
    acceptor.listen(net::socket_base::max_listen_connections);

    for (;;)
        boost::asio::co_spawn(
            acceptor.get_executor(),
            do_session(tcp_stream(co_await acceptor.async_accept()), doc_root),
            [](std::exception_ptr e) {
                if (e)
                    try {
                        std::rethrow_exception(e);
                    } catch (std::exception &e) {
                        std::cerr << "Error in session: " << e.what() << "\n";
                    }
            });
}

int main(int argc, char *argv[])
{
    // Check command line arguments.
    if (argc != 5) {
        std::cerr << "Usage: http-server-awaitable <address> <port> <doc_root> "
                     "<threads>\n"
                  << "Example:\n"
                  << "    http-server-awaitable 0.0.0.0 8080 . 1\n";
        return EXIT_FAILURE;
    }
    auto const address = net::ip::make_address(argv[1]);
    auto const port = static_cast<unsigned short>(std::atoi(argv[2]));
    auto const doc_root = std::make_shared<std::string>(argv[3]);
    auto const threads = std::max<int>(1, std::atoi(argv[4]));

    // The io_context is required for all I/O
    net::io_context ioc{threads};

    // Spawn a listening port
    boost::asio::co_spawn(
        ioc, do_listen(tcp::endpoint{address, port}, doc_root),
        [](std::exception_ptr e) {
            if (e)
                try {
                    std::rethrow_exception(e);
                } catch (std::exception &e) {
                    std::cerr << "Error in acceptor: " << e.what() << "\n";
                }
        });

    // Run the I/O service on the requested number of threads
    std::vector<std::thread> v;
    v.reserve(threads - 1);
    for (auto i = threads - 1; i > 0; --i)
        v.emplace_back([&ioc] { ioc.run(); });
    ioc.run();

    return EXIT_SUCCESS;
}
