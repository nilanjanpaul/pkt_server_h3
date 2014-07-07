// Compile syntax:
// > g++ pkt_server.cpp -lboost_program_options-mt -lboost_thread -o pkt_server

/* A simple server in the internet domain using TCP/UDP to send and receive packets
   The port number is passed as an argument
   This version runs forever, forking off 4 separate threads (two for send and
   two for receive) each of whihc creates a separate thread for each communication)
*/
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <vector>
#include <boost/program_options.hpp>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/format.hpp>
#include <boost/random/random_device.hpp>  // for random packet content
#include <boost/crc.hpp> // for boost::crc_32_type
#include "log4cxx/logger.h"
#include "log4cxx/propertyconfigurator.h"
#include "log4cxx/helpers/exception.h"
#include <boost/date_time/posix_time/posix_time.hpp>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>


namespace po = boost::program_options;
namespace bt = boost::posix_time;


using boost::asio::ip::tcp;
using boost::asio::ip::udp;
using namespace boost;

const int MaxTU = 1440;
const int MinTU = 48;
const int _TIMEOUT = 300; // 5 min
const int BasePortNumber = 5100;


typedef boost::shared_ptr<tcp::socket> socket_ptr;

using namespace log4cxx;
using namespace log4cxx::helpers;

LoggerPtr logger(Logger::getLogger("pkt_server"));
unsigned int nTxThreadSndCnt = 0;
unsigned int nRxThreadSndCnt = 0;

unsigned int gTxSessionKillFlag, gRcvSessionKillFlag, gKillFlag;
bt::ptime gStartTime;
bt::time_duration gtd;
uint32_t gTxBytes = 0;
uint32_t gTxPackets = 0;
uint32_t gRxBytes = 0;
uint32_t gRxGoodPackets = 0;
uint32_t gRxBadPackets = 0;
const int CRCSEQLIM = 500000;
uint32_t crc_sent[CRCSEQLIM];
std::string gOmlFilename;
std::string gOmlServer;
int timeout;
int mode;

void report_fn()
{
  bt::ptime start_time = bt::microsec_clock::local_time();
  bt::ptime last_update = bt::microsec_clock::local_time();
  bt::time_duration td;
  float percent = 0;
  
  while(gKillFlag == 0)
    {
      //this_thread::sleep(bt::milliseconds(1));
      if(gTxPackets == 0)
      {
	start_time = bt::microsec_clock::local_time();
	last_update = bt::microsec_clock::local_time();
      }
      else if(gTxPackets > 0)
	{
	  td = bt::microsec_clock::local_time() - last_update;
	  if ( td.total_seconds() >= 15)
	  {
	    last_update = bt::microsec_clock::local_time();

	    percent = (float)(gRxBytes) / (float)(gTxBytes) * 100.0f;
	    td = bt::microsec_clock::local_time() - start_time;
	    LOG4CXX_INFO(logger, "t=" << td.total_milliseconds() << " msec rx/tx/bad packets=" << gRxGoodPackets << "/" << gTxPackets << "/" << gRxBadPackets << " rx/tx bytes="  << gRxBytes << "/" << gTxBytes << " success=" << percent << "%");
	  }
	  
	  td = bt::microsec_clock::local_time() - start_time;
	  if(td.total_seconds() >= timeout)
	  {
	    LOG4CXX_INFO(logger, timeout << " sec timeout reached - closing connection");
	    percent = (float)(gRxBytes) / (float)(gTxBytes) * 100.0f;
	    td = bt::microsec_clock::local_time() - start_time;
	    LOG4CXX_INFO(logger, " TIME = " << td.total_milliseconds() << " msec rx/tx/bad packets=" << gRxGoodPackets << "/" << gTxPackets << "/" << gRxBadPackets << " rx/tx bytes="  << gRxBytes << "/" << gTxBytes << " success=" << percent << "%");

	    break;
	  }
	}
    }
  if(gKillFlag == 1)
    {
      percent = (float)(gRxBytes) / (float)(gTxBytes) * 100.0f;
      td = bt::microsec_clock::local_time() - start_time;
      LOG4CXX_INFO(logger, " TIME = " << td.total_milliseconds() << " msec rx/tx/bad packets=" << gRxGoodPackets << "/" << gTxPackets << "/" << gRxBadPackets << " rx/tx bytes="  << gRxBytes << "/" << gTxBytes << " success=" << percent << "%");
      gKillFlag = 0;
    }


  gRcvSessionKillFlag = 1;
  gTxSessionKillFlag = 1;

}

void tcp_snd_session(socket_ptr sock)
{
  uint32_t data[(MaxTU/sizeof(uint32_t))+3], counter = 0;
  boost::random::random_device rnd;
  int payload_length,rnd_length;
  int small_pkts = 0;
  try
    {
      std::string cIP = sock->remote_endpoint().address().to_string(); // client IP address
      boost::system::error_code error;
      boost::crc_32_type crc;

      gTxBytes = gTxPackets = 0;
      for (;; counter++)
	{
	  sock->read_some(boost::asio::buffer(data), error);       // read packet request from the client - payload length
	  if(error)
	    {
	      gKillFlag = 1;
	      LOG4CXX_INFO(logger,"Closing Connection");
	      break; // Connection closed cleanly by peer.
	    }

	  payload_length = ntohl( data[0] );

	  //LOG4CXX_INFO(logger, "Request for " << payload_length << " bytes");
	  if (error)
	    payload_length = MaxTU;
	  else if (payload_length > MaxTU)
	    payload_length = MaxTU;
	  else if (payload_length < MinTU)
	    payload_length = MinTU;

	  // Let's find out how many 32 bit words do we need
	  // minus two: for counter and crc
	  if(payload_length < MaxTU)
	    small_pkts= 1;  //set this flag if payload_length <1440
	  rnd_length = (1 + ((payload_length - 1) / sizeof(data[0]))) - 2;
	  gTxBytes += (rnd_length + 2)*4;
	  // Give us some random data
	  rnd.generate( data+2, data+rnd_length );
	  // Put the packet number in there and start with 0 so we can match it on the receiver
	  data[1] = htonl(counter);

	  // Let's find the checksum
	  crc.reset();
	  crc.process_bytes(&data[1],(rnd_length+1)*sizeof(data[0]));
	  data[0] = htonl(crc.checksum());

	  crc_sent[counter] = data[0];
	  //LOG4CXX_INFO(logger, "Sending to " << cIP << " (s#: " << counter << ") checksum [" << std::hex << data[0] << "] = {" << data[2] << "," << data[3] << "," << data[4] << ",...}");
	  // and then send it back
	  boost::asio::write(*sock, boost::asio::buffer(data, payload_length));
	  gTxPackets++;

	}
      if(small_pkts == 1)
	LOG4CXX_INFO(logger, "************************Small pkts requested");
      LOG4CXX_INFO(logger, "Tx Thread count: " << --nTxThreadSndCnt);
    }
  catch (std::exception& e)
    {
      if(small_pkts == 1)
	LOG4CXX_INFO(logger, "************************Small pkts requested");
      LOG4CXX_INFO(logger, "Tx Thread count: " << --nTxThreadSndCnt);
      // std::cerr << "Exception in tcp_snd thread: " << e.what() << "\n";
    }

}


void tcp_rcv_session(socket_ptr sock)
{
  uint32_t data[(MaxTU/sizeof(uint32_t))+3];
  int rnd_length;//, good=0, bad=0, bytes=0;
  bt::ptime starttime,lasttime;
  std::ofstream outdata;
  std::stringstream buffer, filename;
  try
    {
      std::string cIP = sock->remote_endpoint().address().to_string();
      boost::system::error_code error;
      boost::crc_32_type crc;


      while(1)
	{
	  crc.reset();
	  // Handshake - tell other end that receiver is ready to receive packet.
	  data[0] = 0xAABBCC01;
	  sock->write_some( boost::asio::buffer(data, 4), error);
	  if (error)
	    {
	      gKillFlag = 1;
	      break;
	    }

	  size_t bl = sock->read_some(boost::asio::buffer(data), error);
	  if (error)
	    {
	      gKillFlag = 1;
	      break;
	    }

	  int rcv_seq = ntohl(data[1]);
	  //LOG4CXX_DEBUG(logger, "Received " << bl << " from " << cIP << " (s#: " << rcv_seq << ") checksum [" << std::hex << data[0] << "] = {" << data[2] << "," << data[3] << "," << data[4] << ",...}");
	  rnd_length = (1 + ((bl - 1) / sizeof(data[0]))) - 2;
	  // Let's find the checksum
	  if ((rcv_seq >= 0) && (rcv_seq < CRCSEQLIM))
	    {
	      int payload_len = (rnd_length+1)*sizeof(data[0]);
	      //LOG4CXX_DEBUG(logger, "Calculating checksum of " << payload_len << " words");
	      crc.process_bytes(&data[1],payload_len);
	      //LOG4CXX_DEBUG(logger, "Calculating checksum done");
	      if( (crc.checksum() == ntohl(data[0])) && (crc_sent[rcv_seq] == data[0]) )
		{
		  gRxGoodPackets++; gRxBytes += bl;
		  crc_sent[rcv_seq] = 0; // Null the crc so that we won't match if the same packet comes again
		}
	      else
		{
		  gRxBadPackets++;
		}
	    }
	  else
	    {
	      gRxBadPackets++;
	    }
	}

      //float percent = (float)(bytes) / (float)(gTxBytes) * 100.0f;

      LOG4CXX_INFO(logger, "Rx Thread count: " << --nRxThreadSndCnt);
    }
  catch (std::exception& e)
    {
      std::cerr << "Exception in tcp_rcv thread: " << e.what() << "\n";
      LOG4CXX_INFO(logger, "Rx Thread count: " << --nRxThreadSndCnt);
    }
}

void tcp_snd_server(short port)
{
  boost::asio::io_service io_service;

  LOG4CXX_INFO(logger, "Starting TCP sender server at " << port);
  tcp::acceptor a(io_service, tcp::endpoint(tcp::v4(), port));
  socket_ptr sock1;
  for (;;)
    {
      if(gTxSessionKillFlag == 1)
	{
	  if(nTxThreadSndCnt > 0)
	    {
	      sock1->close();
	    }
	  gTxSessionKillFlag = 0;
	  gTxPackets = 0;
	  gTxBytes = 0;
	}
      socket_ptr sock(new tcp::socket(io_service));
      if (nTxThreadSndCnt >= 1) continue;

      a.accept(*sock);
      gTxSessionKillFlag = 0;
      gTxPackets = 0;
      gTxBytes = 0;
      gKillFlag = 0;
 
      boost::thread report_thread(boost::bind(report_fn));
      boost::thread t(boost::bind(tcp_snd_session, sock));
      sock1 = sock;
      LOG4CXX_INFO(logger, "Tx Thread count: " << ++nTxThreadSndCnt);
    }
}

void udp_snd_server(short port)
{
  boost::asio::io_service io_service;

  LOG4CXX_INFO(logger, "Starting UDP sender server at " << port);
  udp::socket sock(io_service, udp::endpoint(udp::v4(), port));
  for (;;)
    {
      char data[MaxTU];
      udp::endpoint sender_endpoint;
      size_t length = sock.receive_from(boost::asio::buffer(data, sizeof(data)), sender_endpoint);
      sock.send_to(boost::asio::buffer(data, length), sender_endpoint);
    }
}

void tcp_rcv_server(short port)
{
  boost::asio::io_service io_service;

  LOG4CXX_INFO(logger, "Starting TCP receiver server at " << port);
  tcp::acceptor a(io_service, tcp::endpoint(tcp::v4(), port));
  socket_ptr sock1;
  for (;;)
    {
      if(gRcvSessionKillFlag == 1)
	{
	  if(nRxThreadSndCnt > 0)
            sock1->close();
	  gRcvSessionKillFlag = 0;
	  gRxGoodPackets = 0;
	  gRxBadPackets = 0;
	  gRxBytes = 0;
	}
      socket_ptr sock(new tcp::socket(io_service));
      if(nRxThreadSndCnt >= 1) continue;

      a.accept(*sock);
      gRcvSessionKillFlag = 0;
      gRxGoodPackets = 0;
      gRxBadPackets = 0;
      gRxBytes = 0;

      boost::thread t(boost::bind(tcp_rcv_session, sock));
      sock1 = sock;
      LOG4CXX_INFO(logger, "Rx Thread count: " << ++nRxThreadSndCnt);
    }
}

void udp_rcv_server(short port)
{
  boost::asio::io_service io_service;

  LOG4CXX_INFO(logger, "Starting UDP receiver server at " << port);
  udp::socket sock(io_service, udp::endpoint(udp::v4(), port));
  for (;;)
    {
      char data[MaxTU];
      udp::endpoint sender_endpoint;
      /*size_t length = */sock.receive_from(boost::asio::buffer(data, sizeof(data)), sender_endpoint);
    }
}

void error(const char *msg)
{
  perror(msg);
  exit(1);
}

int main(int argc, char *argv[])
{
  int port_number,base_port;

  // Configure the logger
  PropertyConfigurator::configure("/usr/local/bin/logconf.prop");
  //setup the program options
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help", "brief description of get/set handlers")
    ("oml-exp-id", po::value<std::string>(&gOmlFilename)->default_value(""), "oml filename")
    ("oml-server", po::value<std::string>(&gOmlServer)->default_value("idb2.orbit-lab.org:3003"), "oml server: idb2.orbit-lab.org:3003")
    ("port", po::value<int>(&port_number)->default_value(BasePortNumber), "Specify base port for the server")
    ("duration", po::value<int>(&timeout)->default_value(_TIMEOUT), "Specify duration")
    ("mode", po::value<int>(&mode)->default_value(0), "Run mode: 0=default, 1=bot_rxtx")
    ;

  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);

  //print the help message
  if (vm.count("help")){
    std::cerr << boost::format("%s") % desc << std::endl;
    return ~0;
  }

  // for(int i = 0; i < 19; i++)
  gRcvSessionKillFlag = 0;

  base_port = boost::lexical_cast<int>(port_number);
  LOG4CXX_INFO(logger, "Starting the server at");
  boost::thread tcpss(tcp_snd_server, base_port);
  boost::thread udpss(udp_snd_server, base_port+1);
  boost::thread tcprs(tcp_rcv_server, base_port+2);
  boost::thread udprs(udp_rcv_server, base_port+3);

  tcpss.join();
  LOG4CXX_INFO(logger, "Server exited.")

    return 0; /* we never get here */
}
