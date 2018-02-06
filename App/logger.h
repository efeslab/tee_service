#ifndef __LOGGER_H
#define __LOGGER_H

#include <string>

using namespace std;

typedef enum : uint16_t
{
    DEBUG = 0,
    INFO  = 1,
    WARNING = 2,
    ERROR = 4,
    CRITICAL = 5

} LogLevel;

class Logger
{
public:
	//members:
	LogLevel mLogLevel;
	string mModuleName;
	
	//methods:
	Logger( string moduleNAme );
	~Logger();

	void Debug( string msg );
	void Info ( string msg );
	void Warn ( string msg );
	void Error( string msg );

private:
	void WriteLog( string prefix, string msg );
	void GetTimeStamp( char *timestamp, size_t size );
};


#endif