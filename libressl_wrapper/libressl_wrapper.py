import unittest
import logging
from ctypes import cdll, CDLL, c_long, c_int, c_float, c_double, c_char_p, create_string_buffer, byref, c_voidp, c_uint8, c_uint32
import sys 
import os

class LibreSSLWrapperError( Exception ):
	def __init__( self ):
		Exception.__init__( self, msg )


class LibreSSLWrapper():
	def __init__( self, sharedObjectPath = './libressl_wrapper.so'  ):
		self.SetupLogger()
		self.implementation = CDLL( sharedObjectPath )  

	def SetupLogger( self ):
		self.log = logging.getLogger( 'LibreSSLWrapper' )
		self.log.setLevel(logging.DEBUG)

		formatter 	   = logging.Formatter('%(asctime)s %(name)-20s %(levelname)-10s %(message)s')
		consoleHandler = logging.StreamHandler()
		consoleHandler.setLevel(logging.DEBUG)
		consoleHandler.setFormatter(formatter)

		self.log.handlers = []
		self.log.addHandler(consoleHandler)	

	def BigNumber( self, value ):
		SUCCESS = 1

		self.implementation.BN_new.restype = c_voidp
		bigNumber = self.implementation.BN_new()

		number_c = c_uint32( value )
		result = self.implementation.BN_set_word( bigNumber, value )
		self.VerifyEqual( result, SUCCESS )

		return bigNumber

	def BigNumber2Int( self, bigNumber ):
		self.log.debug( "BigNumber2Int" )

		FAILED_TRANSLATING = 0xffffffff

		self.implementation.BN_get_word.restype = c_uint32
		number = self.implementation.BN_get_word( bigNumber )

		self.VerifyTrue( number != FAILED_TRANSLATING )

		return number

	def BN_num_bytes( self, bigNumber ):
		numBits  = self.implementation.BN_num_bits( bigNumber )
		numBytes = int( ( numBits + 7 ) / 8 )  #copied from BN_num_bytes macro in include/openssl/bn.h
		
		return numBytes

	def BN_bn2bin( self, bigNumber ):
		numBytes 		= self.BN_num_bytes( bigNumber )
		numberAsBuffer 	= ( c_uint8 * numBytes )()		

		numBytesWritten = self.implementation.BN_bn2bin( bigNumber, numberAsBuffer )

		self.VerifyEqual( numBytesWritten, numBytes )

		return bytearray( numberAsBuffer )

	def VerifyEqual( self, val1, val2 ):
		if val1 == val2:
			return

		logMsg = "Values differ: %d != %d" % ( val1, val2 ) 
		self.log.error( logMsg )
		raise LibreSSLWrapperError( logMsg )

	def VerifyTrue( self, shouldBeTrue ):
		if shouldBeTrue:
			return

		logMsg = "Value is NOT true: %s" % ( shouldBeTrue ) 
		self.log.error( logMsg )
		raise LibreSSLWrapperError( logMsg )



class TestSGXCryptoWrapper(unittest.TestCase):
	def setUp(self):
		print('In setUp()')
		self.libreSSL = LibreSSLWrapper( './libressl_wrapper.so' )

	def tearDown(self):
		print('In tearDown()')

	def test_constructor( self ):
		pass

	def test_BN_num_bytes( self ):
		e = 0x10001

		eAsBigNumber = self.libreSSL.BigNumber( e )
		reconstructed_e = self.libreSSL.BigNumber2Int( eAsBigNumber )

		self.assertEqual( e, reconstructed_e )

		numBytes 	 = self.libreSSL.BN_num_bytes( eAsBigNumber )

		print( "BN_num_bytes( BigNumber( %d ) ) = %d" % ( e, numBytes ) )

	def test_BN_bn2bin( self ):
		e = 0x10001

		eAsBigNumber 	= self.libreSSL.BigNumber( e )

		eAsBuffer = self.libreSSL.BN_bn2bin( eAsBigNumber )

		print( "eAsBuffer:")
		for i in range( len(eAsBuffer) ):
			sys.stdout.write( "0x%02x, " % eAsBuffer[ i ] )
			if ( i + 1 ) % 8 == 0:
				print( "" )
		print( " ")

if __name__ == '__main__':
	unittest.main()

