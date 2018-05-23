Class {
	#name : #ZnOpenSSLSession,
	#superclass : #ZdcAbstractSSLSession,
	#instVars : [
		'readBuffer',
		'writeBuffer',
		'certificateName',
		'serverName',
		'method',
		'context',
		'type',
		'ssl',
		'keyName'
	],
	#classVars : [
		'SSL_CTRL_Options',
		'SSL_ERROR_WANT_READ',
		'SSL_ERROR_WANT_X509_LOOKUP',
		'SSL_ERROR_ZERO_RETURN',
		'SSL_FILETYPE_ASN1',
		'SSL_FILETYPE_PEM',
		'SSL_OP_NO_SSLv2',
		'SSL_OP_NO_SSLv3'
	],
	#category : #'Zinc-OpenSSL'
}

{ #category : #'class initialization' }
ZnOpenSSLSession class >> initialize [
	"self initialize"
	SSL_OP_NO_SSLv2 := 16r00000000.
	SSL_OP_NO_SSLv3 := 16r02000000.
	
	SSL_FILETYPE_PEM := 1.
	SSL_FILETYPE_ASN1 := 2.
	
	SSL_CTRL_Options := 32.
	
	SSL_ERROR_WANT_READ := 2.
	SSL_ERROR_WANT_X509_LOOKUP := 4.
	SSL_ERROR_ZERO_RETURN := 6.
]

{ #category : #operations }
ZnOpenSSLSession >> accept: srcBuffer from: from to: to into: dstBuffer [ 
	
	"0 - Unused
	1 - In accept handshake
	2 - In connect handshake
	3 - Connected"
	| acceptResult writtenBytes |

	"Sets up the real session. Lazy"
	self setup.

	"State in accept handshake"
	state := 1.
	self setBioRead: readBuffer handle bioWrite: writeBuffer handle toSSL: ssl.
	"self setAcceptStateToSsl: ssl."
	
	to >= from ifTrue: [ | written |
		written := readBuffer write: (srcBuffer copyFrom: from to: to).
		written < to ifTrue: [ self error: 'Wrote less :/' ].
	].
	acceptResult := self sslAccept: ssl.
	
	writtenBytes := writeBuffer readInto: dstBuffer size: dstBuffer size.
	acceptResult > 0 ifTrue: [ state := 3 ].
	
	^ (acceptResult < 0 and: [ (self getSSLError: ssl withReturn: acceptResult) ~= SSL_ERROR_WANT_READ "WANT MORE LOVE BABY" ])
		ifTrue: [ -1 ]
		ifFalse: [ writtenBytes ]
]

{ #category : #accessing }
ZnOpenSSLSession >> certificateName: aString [
	
	certificateName := aString.
	type := SSL_FILETYPE_PEM.
	
	keyName := 'key.pem' asFileReference fullName.
]

{ #category : #operations }
ZnOpenSSLSession >> decrypt: srcBuffer from: start to: stop into: dstBuffer [ 

	| written readResult sslError |
	written := readBuffer write: (srcBuffer copyFrom: start to: stop).
	written < stop ifTrue: [ self error: 'Wrote less :/' ].
	
	readResult := self sslRead: ssl inBuffer: dstBuffer ofSize: dstBuffer size.
	
	"If success, go on"
	readResult >= 0 ifTrue: [ ^ readResult ].
	
	sslError := self getSSLError: ssl withReturn: readResult.
	^ ({SSL_ERROR_WANT_READ. SSL_ERROR_ZERO_RETURN. SSL_ERROR_WANT_X509_LOOKUP}
		includes: sslError)
			ifTrue: [ 0 ]
			ifFalse: [ readResult ]
]

{ #category : #accessing }
ZnOpenSSLSession >> enableLogging [

	
]

{ #category : #operations }
ZnOpenSSLSession >> encrypt: srcBuffer from: start to: stop into: dstBuffer [ 
	
	| written writtenBytes sslError encryptedBytes |
	writtenBytes := self sslWrite: ssl fromBuffer: srcBuffer ofSize: stop.
	writtenBytes ~= stop
		ifTrue: [ self error: 'Wrote other than requested???' ].

	encryptedBytes := writeBuffer pendingBytes.
	encryptedBytes > dstBuffer size
		ifTrue: [ self error: 'Destination buffer does not have enough size!' ].
	
	^ writeBuffer readInto: dstBuffer size: encryptedBytes
]

{ #category : #operations }
ZnOpenSSLSession >> ffiLibraryName [

	^ 'libssl'
]

{ #category : #operations }
ZnOpenSSLSession >> getNumberOfEncryptedBytes: bio [

	
]

{ #category : #operations }
ZnOpenSSLSession >> getSSLError: eseselele withReturn: returnCode [

	^ self ffiCall: #(int SSL_get_error(void* eseselele, int returnCode))
]

{ #category : #testing }
ZnOpenSSLSession >> isConnected [
	"Returns true if the SSL handshake has been completed"
	"Returns the current state of the SSL connection:
		0 - Unused
		1 - In accept handshake
		2 - In connect handshake
		3 - Connected"
		
	^ state = 3
]

{ #category : #operations }
ZnOpenSSLSession >> newSSLContext: aMethod [
	
	^ self ffiCall: #(void *SSL_CTX_new(void* aMethod)) module: 'libssl'
]

{ #category : #operations }
ZnOpenSSLSession >> newSSLWithContext: aContext [

	^ self ffiCall: #(void* SSL_new(void* aContext))
]

{ #category : #operations }
ZnOpenSSLSession >> newSSLv23Method [
	
	"ExternalAddress loadSymbol: #DTLS_method module:'libssl'"
	^ self ffiCall: #(void *SSLv23_server_method(void)) module: 'libssl'
]

{ #category : #operations }
ZnOpenSSLSession >> newTSLMethod [
	
	"ExternalAddress loadSymbol: #DTLS_method module:'libssl'"
	^ self ffiCall: #(void *DTLS_method(void)) module: 'libssl'
]

{ #category : #accessing }
ZnOpenSSLSession >> serverName: aString [

	serverName := aString
]

{ #category : #operations }
ZnOpenSSLSession >> setAcceptStateToSsl: eseselele [

	^ self ffiCall: #(int SSL_set_accept_state(void* eseselele))
]

{ #category : #operations }
ZnOpenSSLSession >> setBioRead: bioread bioWrite: biowrite toSSL: eseseele [

	^ self ffiCall: #(int SSL_set_bio(void* eseseele, void* bioread, void* biowrite))
]

{ #category : #operations }
ZnOpenSSLSession >> setCertificateFileToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_use_certificate_file(void* aContext, String certificateName, int type))
]

{ #category : #operations }
ZnOpenSSLSession >> setCipherList: cipherListString toContext: aContext [

	self ffiCall: #(int SSL_CTX_set_cipher_list(void* aContext, String cipherListString))
]

{ #category : #operations }
ZnOpenSSLSession >> setControlCommand: command larg: argument parg: pargument toContext: aContext [
	self
		ffiCall: #(ulong SSL_CTX_ctrl #(void * aContext , int command , ulong argument, void * pargument))
		module: 'libssl'
]

{ #category : #operations }
ZnOpenSSLSession >> setDefaultVerifyPathToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_set_default_verify_paths(void* aContext))
]

{ #category : #operations }
ZnOpenSSLSession >> setOptions: optionFlaggish toContext: aContext [

	"ExternalAddress loadSymbol: #'SSL_CTX_ctrl' module:'libssl'"
	^ self setControlCommand: SSL_CTRL_Options larg: optionFlaggish parg: ExternalAddress null toContext: aContext
]

{ #category : #operations }
ZnOpenSSLSession >> setPrivateKeyFileToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_use_PrivateKey_file(void* aContext, String keyName, int type))
]

{ #category : #accessing }
ZnOpenSSLSession >> setup [

	ssl ifNotNil: [ ^ self ].

	readBuffer := ZnMemoryBIO new setAutoClose.
	writeBuffer := ZnMemoryBIO new setAutoClose.
	method := self newSSLv23Method.
	context := self newSSLContext: method.
	
	"SSLv2 and SSLv3 are deprecated"
	"self setOptions: SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 toContext: context."
	
	"!!WTF@@HELP:ME"
	"self setCipherList: '!ADH:HIGH:MEDIUM:@STRENGTH' toContext: context."
	
	self assert: (self setCertificateFileToContext: context) > 0.
	self assert: (self setPrivateKeyFileToContext: context) > 0.
	
	"self setDefaultVerifyPathToContext: context."
	
	ssl := self newSSLWithContext: context.
]

{ #category : #operations }
ZnOpenSSLSession >> sslAccept: eseselele [

	^ self ffiCall: #(int SSL_accept(void* eseselele))
]

{ #category : #operations }
ZnOpenSSLSession >> sslRead: eseselele inBuffer: dstBuffer ofSize: bufferSize [

	^ self ffiCall: #(long SSL_read(void* eseselele, ByteArray dstBuffer, ulong bufferSize))
]

{ #category : #operations }
ZnOpenSSLSession >> sslWrite: eseselele fromBuffer: srcBuffer ofSize: bufferSize [

	^ self ffiCall: #(long SSL_write(void* eseselele, ByteArray srcBuffer, ulong bufferSize))
]
