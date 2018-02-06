#include "logger.h"
#include <iostream>
#include <iomanip>

Logger::Logger( string moduleNAme )
{
	mModuleName = moduleNAme;
}

Logger::~Logger() {}

void Logger::Debug( string msg ) 
{
	if( mLogLevel > DEBUG )
		return;

	WriteLog( "DEBUG", msg );
}
void Logger::Info( string msg ) 
{
	if( mLogLevel > INFO )
		return;

	WriteLog( "INFO", msg );
}
void Logger::Warn( string msg ) 
{
	if( mLogLevel > WARNING )
		return;

	WriteLog( "WARNING", msg );
}
void Logger::Error( string msg ) 
{
	if( mLogLevel > ERROR )
		return;

	WriteLog( "ERROR", msg );
}

void Logger::WriteLog( string prefix, string msg )
{
	char timestamp[ 100 ] = {0};
	GetTimeStamp( timestamp, 100 );

	std::cout << std::left << std::setw(23) << timestamp << " " << std::left << std::setw(21) << mModuleName << std::left << std::setw(10) << prefix << " " << msg << "\n";
}

void Logger::GetTimeStamp( char *timestamp, size_t size )
{
  time_t rawtime;
  struct tm * timeinfo;
  time (&rawtime);
  timeinfo = localtime(&rawtime);

  strftime(timestamp,size,"%Y-%m-%d_%H-%M-%S",timeinfo);
}