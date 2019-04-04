#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/yield.hpp>

namespace ba = boost::asio;
namespace bs = boost::system;

class EchoServer : public ba::coroutine
{
public:
  EchoServer(ba::io_context & ioContext, uint16_t port);
  void operator()(const bs::error_code & errorCode = bs::error_code(), std::size_t length = 0);
private:
  std::shared_ptr<ba::ip::tcp::acceptor> _acceptor;
  std::shared_ptr<ba::ip::tcp::socket> _socket;
  std::shared_ptr<std::vector<uint8_t>> _buffer;
};

EchoServer::EchoServer(ba::io_context & ioContext, uint16_t port):
  _acceptor(nullptr),
  _socket(nullptr),
  _buffer(nullptr)
{
  _acceptor.reset(new ba::ip::tcp::acceptor(ioContext, ba::ip::tcp::endpoint(ba::ip::tcp::v4(), port)));
}

void EchoServer::operator()(const bs::error_code & errorCode, std::size_t length)
{
  if (!errorCode)
  {
    reenter (this)
    {
      do
      {
        _socket.reset(new ba::ip::tcp::socket(_acceptor->get_io_context()));
        yield _acceptor->async_accept(*_socket, *this);
        
        std::cout
          << "Connected:\n"
          << _socket->remote_endpoint().address().to_string() << ':'
          << _socket->remote_endpoint().port() << std::endl;
        
        fork EchoServer(*this)();
      }
      while (is_parent());
      
      _buffer.reset(new std::vector<uint8_t>(1024));
      do
      {
        yield _socket->async_receive(ba::buffer(*_buffer, _buffer->size()), *this);
        for (unsigned int i = 0; i < length; ++i)
        {
          std::cout << _buffer->at(i);
        }
        yield _socket->async_send(ba::buffer(*_buffer, length), *this);
      }
      while (true);
    }
  }
  else
  {
    std::cerr << "errorCode: " << errorCode.message() << std::endl;
    _socket->close();
  }
}

#include <boost/asio/unyield.hpp>

int main(int argc, char ** argv)
{
  if (argc != 2)
  {
    std::cerr << "Usage: boost-asio-learning-stackless [port]" << std::endl;
    return EXIT_FAILURE;
  }
  
  try
  {
    ba::io_context ioContext;
    ba::signal_set signals(ioContext);
    signals.add(SIGTERM);
    signals.async_wait
    (
      [&ioContext](const bs::error_code & errorCode, int signalNumber)
      {
        if (!errorCode)
        {
          std::cerr << "signalNumber: " << signalNumber << std::endl;
          ioContext.stop();
        }
        else
        {
          std::cerr << "errorCode: " << errorCode.message() << std::endl;
        }
      }
    );
    
    EchoServer(ioContext, std::atoi(argv[1]))();
    ioContext.run();
  }
  catch (bs::error_code ex)
  {
    std::cerr << "boost::system::error_code: " << ex.message() << std::endl;
  }
  catch (std::exception ex)
  {
    std::cerr << "std::exception: " << ex.what() << std::endl;
  }
  
  std::cout << "EXIT_SUCCESS" << std::endl;
  return EXIT_SUCCESS;
}
