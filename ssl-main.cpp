#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace ba = boost::asio;

std::string GetSslErrorString(int line)
{
  unsigned long error = ERR_get_error();
  std::ostringstream ostringstream;
  ostringstream
    << "Line: " << line << '\n'
    << ERR_error_string(error, nullptr) << '\n'
    << "lib: " << ERR_lib_error_string(error) << '\n'
    << "func: " << ERR_func_error_string(error) << '\n'
    << "reason: " << ERR_reason_error_string(error);
  return ostringstream.str();
}

std::string GetX509CertInfo(X509 * x509Cert)
{
  std::size_t issuerSize = 512;
  std::unique_ptr<char []> issuer = std::unique_ptr<char []>(new char [issuerSize]);
  if (!X509_NAME_oneline(X509_get_issuer_name(x509Cert), issuer.get(), issuerSize))
  {
    throw std::runtime_error(GetSslErrorString(__LINE__));
  }
  
  std::size_t subjectSize = 512;
  std::unique_ptr<char []> subject = std::unique_ptr<char []>(new char [subjectSize]);
  if (!X509_NAME_oneline(X509_get_subject_name(x509Cert), subject.get(), subjectSize))
  {
    throw std::runtime_error(GetSslErrorString(__LINE__));
  }
  
  std::ostringstream ostringstream;
  ostringstream
    << "Issuer: " << issuer.get() << '\n'
    << "Subject: " << subject.get();
  return ostringstream.str();
}

bool VerifyCallback(bool preverified, ba::ssl::verify_context & verifyContext)
{
  X509_STORE_CTX * x509StoreContext = verifyContext.native_handle();
  
  std::cout << "=== " << __FUNCTION__ << ": start" << " ===" << std::endl;
  std::cout << std::boolalpha << "preverified: " << preverified << std::noboolalpha << std::endl;
  
  int error = X509_STORE_CTX_get_error(x509StoreContext);
  std::cout << "error: " << X509_verify_cert_error_string(error) << std::endl;
  
  int depth = X509_STORE_CTX_get_error_depth(x509StoreContext);
  std::cout << "depth: " << depth << std::endl;
  
  X509 * mainCert = X509_STORE_CTX_get_current_cert(x509StoreContext);
  if (mainCert)
  {
    std::cout << "mainCert: \n" << GetX509CertInfo(mainCert) << std::endl;
  }
  
  STACK_OF(X509) * x509Stack = X509_STORE_CTX_get1_chain(x509StoreContext);
  while (X509 * certInChain = sk_X509_pop(x509Stack))
  {
    std::cout << "certInChain: \n" << GetX509CertInfo(certInChain) << std::endl;
  }
  
  sk_X509_pop_free(x509Stack, X509_free);
  std::cout << "=== " << __FUNCTION__ << ": end" << " ===" << std::endl;
  return preverified;
}

int main()
{
  try
  {
    std::string hostName = "github.com";
    std::string serviceName = "https";
    std::string hostResource = "/";
    
    ba::io_context ioContext;
    ba::ip::tcp::resolver tcpResolver(ioContext);
    ba::ip::tcp::resolver::results_type resultsType = tcpResolver.resolve(hostName, serviceName);
    
    for (auto iter = resultsType.begin(); iter != resultsType.end(); ++iter)
    {
      std::cout
        << iter->host_name() << ": "
        << iter->endpoint().address().to_string() << ':'
        << iter->endpoint().port() << '\n';
    }
    
    ba::ssl::context sslContext(ba::ssl::context::sslv23);
    sslContext.set_default_verify_paths();
    sslContext.set_verify_mode(ba::ssl::verify_peer);
    sslContext.set_verify_callback(VerifyCallback);
    
    ba::ssl::stream<ba::ip::tcp::socket> sslStream(ioContext, sslContext);
    sslStream.lowest_layer().connect(resultsType->endpoint());
    sslStream.handshake(boost::asio::ssl::stream_base::client);
    
    std::string request =
      std::string("GET ") + hostResource + " HTTP/1.1\r\n" +
      std::string("Host: ") + hostName + "\r\n" +
      std::string("Connection: close\r\n\r\n");
    
    sslStream.write_some(ba::buffer(request, request.size()));
    
    boost::system::error_code errorCode;
    do
    {
      std::vector<char> reply(1024);
      sslStream.read_some(ba::buffer(reply, reply.size()), errorCode);
      if (!errorCode)
      {
        //std::cout << reply.data() << std::endl;
      }
      else
      {
        std::cout << "Error: " << errorCode.message() << std::endl;
        break;
      }
    }
    while (true);
  }
  catch (boost::system::system_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
  catch (std::runtime_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
  
  return EXIT_SUCCESS;
}
