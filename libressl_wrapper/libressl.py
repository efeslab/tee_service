import unittest
import logging
from ctypes import cdll, CDLL, c_long, c_int, c_float, c_double, c_char_p, create_string_buffer, byref, c_voidp, c_uint8, c_uint32, c_uint64, c_void_p, cast, POINTER, addressof
import sys 
import os
import struct
import base64
import time

SUCCESS = 1
NULL    = c_voidp( None )

ECC_CURVES = {
	"secp256k1"  :   714,
	"secp384r1"  :   715,
	"secp521r1"  :   716,
}

AES_KEY_SIZES = [ 128, 192, 256 ]


class LibreSSLWrapperError( Exception ):
	def __init__( self, msg ):
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

	def BN_bin2bn( self, number ):
		CREATE_NEW_BIGNUM 	= NULL
		numberAsBuf 		= struct.pack( "I", number )	

		self.implementation.BN_bin2bn.restype = c_void_p		

		return self.implementation.BN_bin2bn( 	numberAsBuf, 
												c_int( len( numberAsBuf ) ),
												CREATE_NEW_BIGNUM )

	def ParsePublicKeyAsDER( self, publicKeyAsDER ):
		self.log.debug( "ParsePublicKeyAsDER" )
		parsedKey  	  = c_void_p( None )
		derInput      = c_char_p( bytes(publicKeyAsDER) )
		# derInput_ptr2 = c_void_p( addressof( derInput ) )
		derInputSize  = c_long( len( publicKeyAsDER ) )

		result = self.implementation.d2i_PUBKEY(  byref( parsedKey ) ,byref( derInput ), derInputSize )
	
		return parsedKey

	def ParsePrivateKeyAsDER( self, privateKeAsDER ):
		self.log.debug( "ParsePrivateKeyAsDER" )
		EVP_PKEY_RSA  = c_int( 6 )
		parsedKey  	  = c_void_p( None )
		derInput      = c_char_p( bytes(privateKeAsDER) )
		# derInput_ptr2 = c_void_p( addressof( derInput ) )
		derInputSize  = c_long( len( privateKeAsDER ) )

		result = self.implementation.d2i_PrivateKey( EVP_PKEY_RSA, 
													 byref( parsedKey ),
													 byref( derInput ), 
													 derInputSize )
		
		return parsedKey

	def ExtractRSAPublicKey( self, evpKeyPointer ):
		pubKeyAsDER_c   = c_void_p( None )
		size 			= self.implementation.i2d_PUBKEY( evpKeyPointer, byref( pubKeyAsDER_c ) )

		publicKeyAsDER = bytearray( size )
		for byteIdx in range( size ):
			char = c_char_p( pubKeyAsDER_c.value + byteIdx )
			# print( "char = %s" % char.value )
			if len( char.value ) == 0:
				publicKeyAsDER[ byteIdx ] = 0
			else:
				publicKeyAsDER[ byteIdx ] = char.value[ 0 ]

		return publicKeyAsDER


	def EVP_DigestVerifyUpdate( self, ctx, dataToSign ):
		dataToSign_c   = c_char_p( bytes(dataToSign) )
		dataToSignSize = c_uint32( len( dataToSign ) )
		
		if SUCCESS != self.implementation.EVP_DigestUpdate( ctx, dataToSign_c, dataToSignSize ): #defined in evp.h as a macro
			logMsg = "EVP_DigestVerifyUpdate returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

	def EVP_SignUpdate( self, ctx, dataToSign ):
		dataToSign_c   = c_char_p( bytes(dataToSign) )
		dataToSignSize = c_uint32( len( dataToSign ) )
		
		if SUCCESS != self.implementation.EVP_DigestUpdate( ctx, dataToSign_c, dataToSignSize ): #Defined as macro in evp.h
			logMsg = "EVP_SignUpdate returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

	def CreateEVPKey( self, publicKeyPointer ):
		evpKey  = c_voidp( self.implementation.EVP_PKEY_new() )
		if SUCCESS != self.EVP_PKEY_assign_RSA( evpKey, publicKeyPointer ):
			logMsg = "EVP_PKEY_assign_RSA returned value != 1"
			self.log.error( logMsg )
			self.implementation.EVP_PKEY_free( evpKey );
			raise LibreSSLWrapperError( logMsg )

		return evpKey

	def CreateMDContext( self ):
		ctx = c_voidp( self.implementation.EVP_MD_CTX_create() )
		
		if ctx.value is None:
			logMsg = "EVP_MD_CTX_create returned NULL"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

		return ctx

	def GetSHA256Mechanism( self ):
		self.implementation.EVP_sha256.restype = c_void_p
		digestMechanism =  c_void_p( self.implementation.EVP_sha256()  )
		
		if digestMechanism.value is None:
			logMsg = "EVP_sha256 returned NULL"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

		return digestMechanism

	def EVP_DigestInit( self, ctx, digestMechanism ):
		if SUCCESS != self.implementation.EVP_DigestInit_ex( ctx, digestMechanism, NULL ):
			logMsg = "EVP_DigestInit_ex returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

	def EVP_SignInit_ex( self, ctx, digestMechanism ):
		if SUCCESS != self.implementation.EVP_DigestInit_ex( ctx, digestMechanism, NULL ):  #defined in evp.h as a macro
			logMsg = "EVP_SignInit_ex returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

	def EVP_DigestVerifyInit( self, ctx, digestMechanism, evpKey ):
		self.implementation.EVP_DigestVerifyInit.restype = c_int
		
		if SUCCESS != self.implementation.EVP_DigestVerifyInit( ctx, NULL, digestMechanism, NULL, evpKey ):
			logMsg = "EVP_DigestVerifyInit returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

	def EVP_DigestVerifyFinal( self, ctx, signature ):
		self.implementation.ERR_clear_error();

		signature_c   = c_char_p( bytes(signature) )
		signatureSize = c_uint64( len( signature ) )
		
		if SUCCESS != self.implementation.EVP_DigestVerifyFinal( ctx, signature_c, signatureSize ):
			logMsg = "EVP_DigestVerifyFinal returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

	def EVP_SignFinal( self, ctx, dataToSign, evpKey ):
		maxSignatureSize = self.implementation.EVP_PKEY_size( evpKey )

		signature_c   = ( c_uint8 * maxSignatureSize )()
		signatureSize = c_uint32( maxSignatureSize )
		
		if SUCCESS != self.implementation.EVP_SignFinal( ctx, signature_c, byref( signatureSize ), evpKey ):
			logMsg = "EVP_SignFinal returned value != 1"
			self.log.error( logMsg )
			raise LibreSSLWrapperError( logMsg )

		return bytearray( signature_c )[ 0 : signatureSize.value ]

	# def PrintError( self ):
	# 	errCode = c_uint32( self.implementation.ERR_get_error() )
	# 	print( "errCode = %s" % errCode )

	# 	self.implementation.ERR_error_string.restype = c_char_p
	# 	errString = c_char_p( self.implementation.ERR_error_string( errCode, NULL ) )
	# 	print( "errString = %s" % errString.value )		

	def VerifyRSASignature( self, dataToSign, signature, publicKeyPointer ):
		evpKey 			= None
		ctx    			= None

		try:
			# evpKey 			= self.CreateEVPKey( publicKeyPointer )
			evpKey 			= publicKeyPointer
			ctx    			= self.CreateMDContext()
			digestMechanism = self.GetSHA256Mechanism()

			self.EVP_DigestInit( ctx, digestMechanism )
			self.EVP_DigestVerifyInit( ctx, digestMechanism, evpKey )
			self.EVP_DigestVerifyUpdate( ctx, dataToSign )
			self.EVP_DigestVerifyFinal( ctx, signature )

		finally:
			if evpKey != None:
				self.implementation.EVP_PKEY_free( evpKey )
			if ctx != None:
				self.implementation.EVP_MD_CTX_destroy( ctx )

	def VerifyECDSA_OpenSSL_Signature( self, dataToSign, signature, publicKeyPointer ):
		self.VerifyRSASignature(  dataToSign, signature, publicKeyPointer )

	def SignRSA( self, evpKey, dataToSign ):
		ctx    			= None

		try:
			ctx    			= self.CreateMDContext()
			digestMechanism = self.GetSHA256Mechanism()

			self.EVP_SignInit_ex( ctx, digestMechanism )
			self.EVP_SignUpdate( ctx, dataToSign )
			signature = self.EVP_SignFinal( ctx, dataToSign, evpKey )

			return signature
		finally:
			if ctx != None:
				self.implementation.EVP_MD_CTX_destroy( ctx )

		

	def EVP_PKEY_assign_RSA( self, evpKey, publicKeyPointer ):
		EVP_PKEY_RSA = c_int( 6 )
		return self.implementation.EVP_PKEY_assign( evpKey, EVP_PKEY_RSA, publicKeyPointer )

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

	# def CreateRSAKeyPair( self, keySizeInBits ):
	# 	RSA_F4			= 0x10001
	# 	publicExponent 	= self.BN_bin2bn( RSA_F4 )

	# 	print( "publicExponent = %s" % publicExponent )
	# 	self.implementation.RSA_new.restype = c_void_p
	# 	rsaKeyPair = self.implementation.RSA_new()
	# 	print( "Generating..")
	# 	result = self.implementation.RSA_generate_key_ex( 	rsaKeyPair, 
	# 														c_int( keySizeInBits ),
	# 														publicExponent,
	# 														NULL )

	# 	self.implementation.BN_free ( publicExponent );

	# def VerifyRSASignature( self, dataToSign, signature, publicKeyAsDER ):
	# 	raise NotImplementedError() 

class TestSGXCryptoWrapper(unittest.TestCase):
	def setUp(self):
		print('In setUp()')
		self.libreSSL = LibreSSLWrapper( 'libcrypto.so' )

		self.SetupTestRSAKeys()

	def tearDown(self):
		print('In tearDown()')

	def SetupTestRSAKeys( self ):
		self.testKeys = {}
		self.testKeys[ 1024 ] = \
		"""
		MIICWwIBAAKBgQDx620EOYvfIDn2MzgqrKrBwQobtGbCWZW78tjoXrUu/R+FCiAV
		KlpFLBAhPA9lPSMXAB+8C99J3Ch5/VqqjPyWND+8KVFRGbzIOQ8t1DUFpWaAtU3O
		2gCoavToOzcWM/59ArDcoEhi6IDej+K5zse/2LNq5JkDUaKtcSQofF8UFQIDAQAB
		AoGAF1RMvwuNoYbKECQAVp0wGl8zSlirUDKzbdyNblszvcRLNdk0HtZmviTxqULR
		eUHcEGvCo6/BaK4CeUElbS0LboC6YGIgcekZDMU+ymYEMTXvvU5WtTRK9Qgey4YH
		nBBR8yTBEUVaHOhsWR3ji0k6ZDAexlw3Ov4kbMnTYkNxQEECQQD81YoHRoc3Pa6E
		8Gv5CtP4uQ6xrCrwUk+IzZC6WPVyJyWFXn0za/NIwDHHras+ALZu3FAR8zid6/Fn
		3YJgpHknAkEA9PLmcl+Gvmgt3SFdNKjt3Jk5DyJ4C2AyhVH4CX1537v7MAby7qsW
		uz7+BzVVVt3TMfvIt4ZkFZnGegniwNo2YwJAN0SelZSPPj4XhivgDmKVj4s0cRZH
		lJ0JkcgN2Q5VKQzxoMPU7oaseby5pQKLqlQRjQ5P2nymZa8L6D59n46UhQJAJwQ1
		zswGg3fGrm1tEkFCOhwx6YY9BtrY0UGgN6rD6e5gcWL5+ShJY6QCBJXrNP36cQDB
		FPKUKJio87F1a/CWLwJAX3ZvnfFUVAdFc9vTAuXJndFJfHHJfDYdN3eKhQcZ1BYP
		KAVhkRz2F2si3G6DybCUQukyRW4xuKQL2niFqGSZzQ==
		"""

		self.testKeys[ 2048 ] = \
		"""
		MIIEpQIBAAKCAQEA9OvSoeX01UYnyPx8z3HgCbxfD9vNeoX1QkkUyl0nRWIjjYCp
		BQaMp2K9tCDsOfxN86krmblE5a3/mEiQsbeMrznF2upQ7OHaZgJtXrVPw5ihRI05
		w7KF0BJ4paftKjV2J4+PClQTXj+BKhb8stilQzPkvbmN6pWvnSdKb0H78dLpW/lL
		gy36I8KQZIdMIsn7oxpXaUS9Yf8Ij5pyeJHo9dJ7r5ycVC0psxP9giM6/tJQBfhM
		dxT3Aw1SisgeMiAeqa+EEIQ07a0spkc3uHHzWoEHQQj3YYI4cCNqJPliGpD3TGHo
		UPsxgUP8zo5aFTqMshdRMItIq3eXwU7gYDQCFQIDAQABAoIBAQCS5k7zpAVxVh7O
		wgHqOpbxv/YUgPWBo48zLro1liHTz8UbPiwiQ4dhbivyOjz1mor2tmTcUu8sA2zm
		Xb/LmBfdkX1GjHv1WJGx1Yrb30v0OTug7kPTSORRpIKQeWQaiO5RVB2rSDpFsTk7
		kYYHj0GwSRPNZ9ni9dzbGZHfoWgH5hiC2zYPEgKB+pcq1zAUiGb5d/QlHmUoJFVX
		WVaqInyBLQoXMLBOwnbwur3nHF/fHOnpsFczLKVBRbOqTAf3WhvzIsAdMPdJJG3Z
		lVn6IXWEECeQLAMEerLYoMQW1Xno960OJh4Bbrc68ojCNvMRDcSgi1S8PUbyZjXM
		1eC5iiQBAoGBAP2xd82rCi6xr/ivc1Rt1CEXxtM3XtlN93mKfSFBq8jw7U9b++Lt
		y6zVKCsmjNrg2Cy1ZJqenycRl7nVCnWI1XtQY8jmGQ9ik9vYDLHbKBvS0gNLBdvo
		VUgJcMsydZHc45hXDfwqLZwF7ywL8rbbjbTVdyHlyFMfij0UynD/eslVAoGBAPcl
		74y6/RljqNHD1VlLZl6pPUje26NgvTNMMHo4vbQKkG9hLqAiZYO5NG8RCqVw+C1u
		d+s9BE6CzYmZvQTVJbqT8cHIb1Zz6meqO1VV2spJTrVj2DUGnppBhqSGV6BsCX++
		hchPC/HmE1NzmSDeIK37uwIzfDX41mb53SdMpVXBAoGBAJ0D4/RlMg4oZ5Nxc94D
		g9Ffl+1OTeQM/2g4MK4OqTXa9+WwNrwDFZZI722VlIQ7uVAijLuuBS73EoMvuiN4
		pziFTt0enNAK4RymIWVLEQ33c4gaPOwYZgAJ58e72UyH/E1jRAKYUFZKzfbjBjvq
		s1AC9pMCVvQrhzG61nkNhn9pAoGBAMIfVezf4nTSxoMcorMkeh/YJn7aLQJCtdlY
		+qrFbpu/wHr7hjfZTIsOKZUjeY1BEm382sw2fO995hsyWjk1ghDuq3FeEbWCDpem
		Kjx41wUUV3I6HlRoAqN+3FbV/nXO5hckesg+7k7uPDfMEHa0gk6l7tlnvyRVc3Im
		yAJaPXMBAoGATu6XwcCUiW1abkVrTkCAb9G5P7GawdznroPE0guYVUaA952lUP77
		Jxyyz0tMgUE1qH9PWWxkjnHkBnTLvKQoqAW68RHwB7YhI4ZnKFuGLc0F+dcjdteB
		z+L8TipzrgVUN5r9/uXAeCpokRnzbQ/65DT0v0OIdvadbLArWKVH2os=
		"""

		self.testKeys[ 4096 ] = \
		"""
		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
		"""

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

	# # The following test is time consuming:
	# def test_RSASigningSpeed( self ):
	# 	NUM_OPERATIONS = { 1024 : 100000, 2048 : 100000, 4096 : 10000 }

	# 	for keySize, privateKeyAsBase64 in self.testKeys.items():
	# 		privateKeyAsDER = base64.b64decode( privateKeyAsBase64 )
	# 		evpPrivateKey	= self.libreSSL.ParsePrivateKeyAsDER( privateKeyAsDER )		
	# 		publicKeyAsDER 	= self.libreSSL.ExtractRSAPublicKey( evpPrivateKey )
	# 		evpPublicKey    = self.libreSSL.ParsePublicKeyAsDER( publicKeyAsDER )

	# 		dataToSign = bytearray( os.urandom( 1024 ) )

	# 		startTime = time.time()
	# 		for i in range( NUM_OPERATIONS[ keySize ] ):
	# 			signature  = self.libreSSL.SignRSA( evpPrivateKey, dataToSign )
	# 		totalTime = time.time() - startTime
	# 		# dataToSign[ 10 ] ^=  1
	# 		self.libreSSL.VerifyRSASignature( bytes( dataToSign ), signature, evpPublicKey )

	# 		#print performance:
	# 		print( "#" * 50 )
	# 		print( "Key size: %d, Total time: %f, num operations: %d, num operations per second: %f" % \
	# 			( keySize, totalTime, NUM_OPERATIONS[ keySize ] , NUM_OPERATIONS[ keySize ] / totalTime ) )
	# 		print( "#" * 50 )



if __name__ == '__main__':
	unittest.main()

