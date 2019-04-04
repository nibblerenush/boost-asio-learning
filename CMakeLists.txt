cmake_minimum_required(VERSION 3.0)
project(boost-asio-learning)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)

find_package(Boost REQUIRED COMPONENTS system regex date_time)
if(${Boost_FOUND})
  message("BOOST VERSION: " ${Boost_VERSION})
  message("BOOST INCLUDE DIR: " ${Boost_INCLUDE_DIRS})
  message("BOOST LIBRARIES DIR: " ${Boost_LIBRARY_DIRS})
  message("BOOST LIBRARIES: " ${Boost_LIBRARIES})
endif()

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  message("OPENSSL_VERSION: " ${OPENSSL_VERSION})
  message("OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES})
endif()

find_package(Threads REQUIRED)
if(${Threads_FOUND})
  message("CMAKE_THREAD_LIBS_INIT: " ${CMAKE_THREAD_LIBS_INIT})
endif()

set(EXPORTED_TARGETS_BOOST_ASIO
  Boost::system
  Boost::regex
  Boost::date_time
  Threads::Threads)

set(EXPORTED_TARGETS_OPEN_SSL
  OpenSSL::Crypto
  OpenSSL::SSL)

add_executable(${PROJECT_NAME}-ssl ssl-main.cpp)
set_property(TARGET ${PROJECT_NAME}-ssl PROPERTY CXX_STANDARD 14)
target_link_libraries(${PROJECT_NAME}-ssl PRIVATE ${EXPORTED_TARGETS_BOOST_ASIO} ${EXPORTED_TARGETS_OPEN_SSL})

add_executable(${PROJECT_NAME}-stackless stackless-main.cpp)
set_property(TARGET ${PROJECT_NAME}-stackless PROPERTY CXX_STANDARD 14)
target_link_libraries(${PROJECT_NAME}-stackless PRIVATE ${EXPORTED_TARGETS_BOOST_ASIO})
