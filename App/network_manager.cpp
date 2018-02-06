#include "network_manager.h"
#include <fcntl.h>
#include <errno.h>
#include <sstream>
#include <sys/ioctl.h>

NetworkManager::NetworkManager() : 	mListenfd		( -1 ), 
									mClientSocketfd	( -1 ),
									mLogger         ( "NetworkManager" )
{
	mLogger.mLogLevel = INFO;
}

NetworkManager::~NetworkManager() 
{}

void NetworkManager::ReportErrorAndExit(const char *msg)
{
	mLogger.Error( msg );
    perror(msg);
    exit(1);
}

void NetworkManager::InitSocket( int port )
{
    struct sockaddr_in serverAddress;  

    mListenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (mListenfd < 0) 
        ReportErrorAndExit("ERROR opening socket");

    bzero((char *) &serverAddress, sizeof(serverAddress));
    
    serverAddress.sin_family        = AF_INET;
    serverAddress.sin_addr.s_addr   = INADDR_ANY;
    serverAddress.sin_port          = htons( port ); 

    int enable = 1;
    if ( setsockopt(mListenfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1 )
	    ReportErrorAndExit("setsockopt");

    if (bind(   mListenfd, 
                (struct sockaddr *) &serverAddress,
                sizeof(serverAddress)   ) 
                                        < 0) 
              ReportErrorAndExit("ERROR on binding");

    listen(mListenfd, 1); 
}

void NetworkManager::AcceptIncommingConnection()
{
    mClientAddressSize = sizeof( mClientAddress );
    mClientSocketfd    = accept( mListenfd, 
                                (struct sockaddr *) &mClientAddress, 
                                &mClientAddressSize );
    if (mClientSocketfd < 0) 
          ReportErrorAndExit("ERROR on accept");

    int flags = 0;
    if ( ( flags = fcntl(mClientSocketfd, F_GETFL, 0) ) < 0 ) 
    	ReportErrorAndExit("Getting flags");
	
	if( fcntl(mClientSocketfd, F_SETFL, flags | O_NONBLOCK) < 0) 
		ReportErrorAndExit("setting O_NONBLOCK");
	

    mLogger.Info( "Got new connection!\n" );

    // close( mClientSocketfd );
    // close( mListenfd );
    // printf( "Closed all sockets\n" );
}

void NetworkManager::CloseConnectionAndWaitForNextOne()
{
	mLogger.Info( "Closing client socket\n" );
	close( mClientSocketfd );
	AcceptIncommingConnection();
}

void NetworkManager::Start( int port )
{
	InitSocket( port );
	AcceptIncommingConnection();
}

void NetworkManager::GetBytesFromSocket( void* buff, size_t numBytesToRead )
{
	uint16_t bytesReceivedSoFar = 0;
	while( bytesReceivedSoFar < numBytesToRead )
	{
		int bytesReceived = read(mClientSocketfd, 
								 (uint8_t*)buff + bytesReceivedSoFar, 
								 numBytesToRead - bytesReceivedSoFar );
		
	    if (bytesReceived < 0) 
	    {
	    	if (errno == EAGAIN || errno == EWOULDBLOCK)
	    	{
	    		continue;
	    	}
	    	else
	    	{
	    		ReportErrorAndExit("ERROR reading from socket");
	    	}
	    }

	    bytesReceivedSoFar += bytesReceived;
	}	
}

bool NetworkManager::IsMsgPending()
{
	static int count;
	ioctl( mClientSocketfd, FIONREAD, &count );
	
	return count > 0;
}

OpenSSMStatus NetworkManager::GetNextMessage(OpenSSMMsg& msg) 
{
	GetBytesFromSocket( &msg.header, sizeof( msg.header ) );

	if( msg.header.totalLength >= MSG_BUFFER_SIZE )
	{
		ostringstream 	logMsg;
		logMsg << "Msg too big: header.totalLength = " << msg.header.totalLength 
			   << "; MSG_BUFFER_SIZE = "  << MSG_BUFFER_SIZE << "; TERMINATING SOCKET!";
		mLogger.Error( logMsg.str() );
		close( mClientSocketfd );
		mClientSocketfd = -1;

		return OPENSSM_BAD_MSG_HEADER;
	}

	GetBytesFromSocket( msg.asBuffer + sizeof( msg.header ), 
					    msg.header.totalLength - sizeof( msg.header ) );

    return OPENSSM_SUCCESS;
}

OpenSSMStatus NetworkManager::SendMessage(OpenSSMMsg& msg)
{
	ostringstream 	logMsg;
	uint16_t 		bytesSentSoFar = 0;
	uint16_t 		numBytesToSend = msg.header.totalLength;

    logMsg << "Sending " << numBytesToSend << " bytes";
    mLogger.Debug( logMsg.str() );
	
    // logMsg.str( "" );
    // logMsg << "Msg:\n";
    // for( uint32_t i = 0; i < msg.header.totalLength; ++i )
    // {
    //     logMsg << "0x" << std::hex << (uint32_t)msg.asBuffer[ i ] << ", ";
    //     if( ( i + 1 ) % 8 == 0 )
    //         logMsg << std::endl;
    // }
    // logMsg << "\n";
    // mLogger.Debug( logMsg.str() );

	int bytesSent;
	while( bytesSentSoFar < numBytesToSend )
	{
		bytesSent = write( 	mClientSocketfd, 
							msg.asBuffer + bytesSentSoFar, 
							msg.header.totalLength - bytesSentSoFar );

		if( bytesSent < 0 ){
			ReportErrorAndExit("ERROR writing to socket");
		}

		bytesSentSoFar += bytesSent;
	}
	mLogger.Debug( "############ Done sending\n");

    return OPENSSM_SUCCESS;
}