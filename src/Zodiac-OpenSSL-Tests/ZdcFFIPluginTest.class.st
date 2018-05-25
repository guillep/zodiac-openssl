Class {
	#name : #ZdcFFIPluginTest,
	#superclass : #TestCase,
	#category : #'Zodiac-OpenSSL-Tests'
}

{ #category : #tests }
ZdcFFIPluginTest >> testImplementation [
	"It tests that the implementation used is the one of the FFI"

	self assert: ZnNetworkingUtils default sslSessionClass equals: ZdcOpenSSLSession
]
