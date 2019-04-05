#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/spawn.hpp>

namespace ba = boost::asio;
namespace bs = boost::system;

class Session: public std::enable_shared_from_this<Session>
{
public:
  Session(ba::ip::tcp::socket && socket);
  void start();
  
private:
  ba::ip::tcp::socket _socket;
  ba::io_context & _ioContext;
  std::vector<uint8_t> _buffer;
};

Session::Session(ba::ip::tcp::socket && socket):
  _socket(std::move(socket)),
  _ioContext(_socket.get_io_context()),
  _buffer(1024)
{}

void Session::start()
{
  auto self(shared_from_this());
  ba::spawn
  (
    _ioContext,
    [this, self](ba::yield_context yield)
    {
      try
      {
        while (true)
        {
          std::size_t length = _socket.async_receive(ba::buffer(_buffer, _buffer.size()), yield);
          for (unsigned int i = 0; i < length; ++i)
          {
            std::cout << _buffer.at(i);
          }
          _socket.async_send(ba::buffer(_buffer, length), yield);
        }
      }
      catch (bs::system_error ex)
      {
        _socket.close();
        std::cerr << "bs::system_error: " << ex.what() << std::endl;
      }
      catch (std::exception & ex)
      {
        _socket.close();
        std::cerr << "std::exception: " << ex.what() << std::endl;
      }
    }
  );
}

int main(int argc, char ** argv)
{
  if (argc != 2)
  {
    std::cerr << "Usage: " << argv[0] << " [port]" << std::endl;
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
    
    ba::spawn
    (
      ioContext,
      [&](ba::yield_context yield)
      {
        ba::ip::tcp::acceptor acceptor(ioContext,
                                       ba::ip::tcp::endpoint(ba::ip::tcp::v4(), std::atoi(argv[1])));
        
        while (true)
        {
          bs::error_code errorCode;
          ba::ip::tcp::socket socket(ioContext);
          acceptor.async_accept(socket, yield[errorCode]);
          
          std::cout
            << "Connected:\n"
            << socket.remote_endpoint().address().to_string() << ':'
            << socket.remote_endpoint().port() << std::endl;
          
          if (!errorCode)
          {
            std::make_shared<Session>(std::move(socket))->start();
          }
          else
          {
            std::cerr << "errorCode: " << errorCode.message() << std::endl;
          }
        }
      }
    );
    ioContext.run();
  }
  catch (bs::system_error ex)
  {
    std::cerr << "bs::system_error: " << ex.what() << std::endl;
  }
  catch (std::exception & ex)
  {
    std::cerr << "std::exception: " << ex.what() << std::endl;
  }
  
  std::cout << "EXIT_SUCCESS" << std::endl;
  return EXIT_SUCCESS;
}
