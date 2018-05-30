"
I represent a X509 certificate store in openSSL.

I am an opaque external object. 
I should be used through the functions exposed in OpenSSL.

If you keep a reference to me take care that I am nulled when the image is closed. 
So maybe you don't want to keep a reference to me.

I am only created by the OpenSSL functions. 
I can add certificates to the underlying openssl object.
"
Class {
	#name : #ZdcX509CertificateStore,
	#superclass : #FFIOpaqueObject,
	#classVars : [
		'ERR_LIB_X509',
		'X509_R_CERT_ALREADY_IN_HASH_TABLE'
	],
	#category : #'Zodiac-OpenSSL-Certificates-Base'
}

{ #category : #'library path' }
ZdcX509CertificateStore class >> ffiLibraryName [

	^ ZdcOpenSSLLibrary
]

{ #category : #'class initialization' }
ZdcX509CertificateStore class >> initialize [
	ERR_LIB_X509 := 11.
	X509_R_CERT_ALREADY_IN_HASH_TABLE := 101
]

{ #category : #adding }
ZdcX509CertificateStore >> addCertificate: aZdcX509Certificate [

	(self primAddCertificate: aZdcX509Certificate) ~= 1
		ifTrue: [ self handleAddingError: aZdcX509Certificate  ]
]

{ #category : #'library path' }
ZdcX509CertificateStore >> ffiLibraryName [
	^ self class ffiLibraryName
]

{ #category : #errors }
ZdcX509CertificateStore >> handleAddingError: aZdcX509Certificate [
	| lib errorCode errorMsgBuffer errorMsg |
	
	lib := ZdcOpenSSLLibrary uniqueInstance.
	errorCode := lib getLastErrorCode.
	

	"If the error is a duplicated certificate, we ignore it."
	(((lib getErrorLib: errorCode) = ERR_LIB_X509) and: [ (lib getErrorReason: errorCode) = X509_R_CERT_ALREADY_IN_HASH_TABLE] )
		ifTrue: [ ^self ].

	errorMsgBuffer := ByteArray new: 500.
		
	lib getLastErrorStringFromErrorCode: errorCode buffer: errorMsgBuffer.
	errorMsg := 'Adding ' , aZdcX509Certificate name , ':', errorMsgBuffer utf8Decoded.
	
	self error: errorMsg.
]

{ #category : #adding }
ZdcX509CertificateStore >> primAddCertificate: aZdcX509Certificate [ 
	
	^ self ffiCall: #(int X509_STORE_add_cert(self, ZdcX509Certificate* aZdcX509Certificate))
]
