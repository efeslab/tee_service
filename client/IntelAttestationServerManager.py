import unittest
import requests
import pprint
import ssl
import binascii 
import json
import config

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager



IAS_ADDRESS 		= "https://test-as.sgx.trustedservices.intel.com"
CLIENT_CERTIFICATE 	= ( config.REPOSITORY_ABSOLUTE_PATH + '/client/client_certificates/client.crt.pem',
						config.REPOSITORY_ABSOLUTE_PATH + '/client/client_certificates/private_key.pem')
DEFAULT_GID 		= 0xd6e
SIGNATURE_REVOCATION_LIST_REQUEST = "/attestation/sgx/v2/sigrl/%08X" 
VERIFY_QUOTE_REQUEST  			  = "/attestation/sgx/v2/report" 

class TLSv_1_2_Adapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)

class IntelAttestationServerError( Exception ):
	def __init__( self, msg, errCode  ):
		Exception.__init__( self, msg )
		self.errorCode = errCode

class IntelAttestationServerManager:
	def __init__( self ):
		pass
		# self.certificatePath = certificatePath
		# self.privateKeyPath  = privateKeyPath

	def GetSignatureRevocationList( self, groupID ):
		STATUS_OK 		 = 200
		STATUS_NOT_FOUND = 404

		requestSigRL_URL = IAS_ADDRESS + SIGNATURE_REVOCATION_LIST_REQUEST % groupID

		connection = requests.Session()
		connection.mount( "https://", TLSv_1_2_Adapter())
		result = connection.get( requestSigRL_URL, cert=CLIENT_CERTIFICATE )

		pprint.pprint( "======== response: %s" % result )
		pprint.pprint( "======== contents: %s" % result.content )
		pprint.pprint( result.headers )
		connection.close()
		
		if result.status_code == STATUS_OK:
			return  result.content

		raise IntelAttestationServerError( "Group ID not found!", result.status_code )

	def VerifyQuote( self, rawQuote ):
		INTEL_PUBLIC_KEY = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFi
							aGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhk
							KWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQj
							lytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwn
							XnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KA
							XJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4
							tQIDAQAB"""


		base64Quote = binascii.b2a_base64( rawQuote ).decode( 'ascii' )
		payload     = { 'isvEnclaveQuote' : base64Quote } #, 'pseManifest': None, 'nonce' : None }
		jsonPayload = json.dumps( payload )
		requestURL  = IAS_ADDRESS + VERIFY_QUOTE_REQUEST
		headers 	= { "Content-Type" : "application/json" }

		connection = requests.Session()
		connection.mount( "https://", TLSv_1_2_Adapter())
		result = connection.post( requestURL, data=jsonPayload, headers=headers, cert=CLIENT_CERTIFICATE )



		iasResults = json.loads( result.content.decode( 'ascii' )  )
		# pprint.pprint( "signature: %s" % result.headers[ 'x-iasreport-signature' ] )
		# pprint.pprint( "data: |%s|" % result.content )
		pprint.pprint( iasResults )

		# #Verify Intel's signature:
		# import base64
		# from libressl import LibreSSLWrapper
		# libreSSLSharedObjectPath = '../libressl_wrapper/libressl_wrapper.so'
		# libreSSL = LibreSSLWrapper( libreSSLSharedObjectPath )

		# intelPubKeyAsDER = base64.b64decode( INTEL_PUBLIC_KEY )
		# intelPubKey 	 = libreSSL.ParsePublicKeyAsDER( intelPubKeyAsDER )
		# signedData = result.content
		# signedData = bytearray( signedData )
		# # signedData[ 10 ] ^= 1 
		# signature = base64.b64decode( result.headers[ 'x-iasreport-signature' ] )
		# libreSSL.VerifyRSASignature( signedData, signature, intelPubKey )

		connection.close()	
		
		if iasResults[ 'isvEnclaveQuoteStatus' ] != 'OK':			
			raise IntelAttestationServerError( "Attestation failed", 0x0 )

	def IsQuoteValid( self, quote ):
		return False

class TestIASManager(unittest.TestCase):
	def setUp(self):
		print('In setUp()')
		self.iasManager = IntelAttestationServerManager()

	def tearDown(self):
		print('In tearDown()')

	def test_getSignatureRevocationList_defualtGID( self ):
		sigRL = self.iasManager.GetSignatureRevocationList( groupID = DEFAULT_GID )
		self.assertEqual( sigRL, b'' )

	def test_getSignatureRevocationList_badGID( self ):
		exceptionCaught = False

		try:
			sigRL = self.iasManager.GetSignatureRevocationList( groupID = 0xdeadbeef )
		except IntelAttestationServerError as e:
			self.assertEqual( e.errorCode, 404 )
			exceptionCaught = True

		self.assertTrue( exceptionCaught )

if __name__ == '__main__':
	unittest.main()