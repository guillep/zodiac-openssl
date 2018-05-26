Class {
	#name : #ZdcOpenSSLSession,
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
		'state',
		'privateKeyName',
		'certificateValidation'
	],
	#classVars : [
		'SSL_CTRL_SET_TLSEXT_HOSTNAME',
		'SSL_ERROR_WANT_READ',
		'SSL_ERROR_WANT_X509_LOOKUP',
		'SSL_ERROR_ZERO_RETURN',
		'SSL_FILETYPE_ASN1',
		'SSL_FILETYPE_PEM',
		'SSL_OP_NO_SSLv2',
		'SSL_OP_NO_SSLv3',
		'SSL_VERIFY_CLIENT_ONCE',
		'SSL_VERIFY_FAIL_IF_NO_PEER_CERT',
		'SSL_VERIFY_NONE',
		'SSL_VERIFY_PEER',
		'SSL_VERIFY_POST_HANDSHAKE',
		'TLSEXT_NAMETYPE_host_name',
		'X509_V_OK'
	],
	#category : #'Zodiac-OpenSSL-Core'
}

{ #category : #'as yet unclassified' }
ZdcOpenSSLSession class >> X509_V_OK [

	^ X509_V_OK
]

{ #category : #installation }
ZdcOpenSSLSession class >> ensureZincPluggableSession [

	(ZnNetworkingUtils hasSlotNamed: #sslSessionClass)
		ifTrue: [ ^ self ].
	
	ZdcSecureSocketStream compile: 'sslSessionClass
	^ ZnNetworkingUtils default sslSessionClass'.
	
	ZnNetworkingUtils addSlot: 'sslSessionClass'.
	ZnNetworkingUtils compile: 'sslSessionClass
	^ sslSessionClass ifNil: [ 
 		sslSessionClass := Smalltalk globals at: #ZdcPluginSSLSession ifAbsent: [ nil ] ]'.
	ZnNetworkingUtils compile: 'sslSessionClass: aClass
		sslSessionClass := aClass'.
]

{ #category : #'class initialization' }
ZdcOpenSSLSession class >> initialize [
	"self initialize"
	SSL_OP_NO_SSLv2 := 16r00000000.
	SSL_OP_NO_SSLv3 := 16r02000000.
	
	SSL_FILETYPE_PEM := 1.
	SSL_FILETYPE_ASN1 := 2.

	SSL_ERROR_WANT_READ := 2.
	SSL_ERROR_WANT_X509_LOOKUP := 4.
	SSL_ERROR_ZERO_RETURN := 6.
	
	X509_V_OK := 0.
	
	SSL_VERIFY_NONE := 0.
	SSL_VERIFY_PEER := 1.
	SSL_VERIFY_FAIL_IF_NO_PEER_CERT := 2.
	SSL_VERIFY_CLIENT_ONCE := 4.
	SSL_VERIFY_POST_HANDSHAKE := 8.
	
	SSL_CTRL_SET_TLSEXT_HOSTNAME := 55.
	TLSEXT_NAMETYPE_host_name := 0
]

{ #category : #installation }
ZdcOpenSSLSession class >> install [
	<script>
	"self install"
	self ensureZincPluggableSession.
	ZnNetworkingUtils default sslSessionClass: self.
]

{ #category : #operations }
ZdcOpenSSLSession >> accept: srcBuffer from: start to: stop into: dstBuffer [ 
	| acceptResult |

	self ensureSetupDoing: [ self setAcceptState ].
	self write: srcBuffer from: start to: stop intoBio: readBuffer.
	
	"If an error occurred, it may have happened that SSL wants to read more bytes.
	In that case, we continue, otherwise we fail with a -1"
	acceptResult := self primitiveAccept.
	(acceptResult < 0 and: [ self wantsReadMore: acceptResult ])
		ifTrue: [ ^ -1 ].

	self setConnectedState.
	^ writeBuffer readInto: dstBuffer size: dstBuffer size
]

{ #category : #accessing }
ZdcOpenSSLSession >> certificateName [
	"The name of the local certificate to provide to the remote peer"

	^ certificateName
]

{ #category : #accessing }
ZdcOpenSSLSession >> certificateName: aString [
	
	certificateName := aString
]

{ #category : #operations }
ZdcOpenSSLSession >> connect: srcBuffer from: start to: stop into: dstBuffer [
	| connectResult |
	
	self ensureSetupDoing: [ self setConnectState ].
	self write: srcBuffer from: start to: stop intoBio: readBuffer.
	
	"If an error occurred, it may have happened that SSL wants to read more bytes.
	In that case, we continue, otherwise we fail with a -2 because the client is checking for it"
	connectResult := self primitiveConnect.
	connectResult <= 0 ifTrue: [ 
		^ (self wantsReadMore: connectResult)
			ifTrue: [ writeBuffer readInto: dstBuffer size: dstBuffer size ]
			ifFalse: [ -2 ]].

	self setConnectedState.
	certificateValidation validateCertificate: self.
	^ 0
]

{ #category : #operations }
ZdcOpenSSLSession >> decrypt: srcBuffer from: start to: stop into: dstBuffer [ 

	| written readResult sslError |
	written := readBuffer write: (srcBuffer copyFrom: start to: stop).
	written < stop ifTrue: [ self error: 'Wrote less :/' ].
	
	readResult := self sslReadIntoBuffer: dstBuffer ofSize: dstBuffer size.
	
	"If success, go on"
	readResult >= 0 ifTrue: [ ^ readResult ].
	
	sslError := self getSSLErrorForReturnCode: readResult.
	^ ({SSL_ERROR_WANT_READ. SSL_ERROR_ZERO_RETURN. SSL_ERROR_WANT_X509_LOOKUP}
		includes: sslError)
			ifTrue: [ 0 ]
			ifFalse: [ readResult ]
]

{ #category : #initialization }
ZdcOpenSSLSession >> destroy [
	
	"WHAT?"
]

{ #category : #initialization }
ZdcOpenSSLSession >> doNotValidateCertificate [

	certificateValidation := ZdcNoCertificateValidation new
]

{ #category : #accessing }
ZdcOpenSSLSession >> enableLogging [

	
]

{ #category : #operations }
ZdcOpenSSLSession >> encrypt: srcBuffer from: start to: stop into: dstBuffer [ 
	
	| writtenBytes encryptedBytes |
	writtenBytes := self sslWriteFromBuffer: srcBuffer ofSize: stop.
	writtenBytes ~= stop
		ifTrue: [ self error: 'Wrote other than requested???' ].

	encryptedBytes := writeBuffer pendingBytes.
	encryptedBytes > dstBuffer size
		ifTrue: [ self error: 'Destination buffer does not have enough size!' ].
	
	^ writeBuffer readInto: dstBuffer size: encryptedBytes
]

{ #category : #setup }
ZdcOpenSSLSession >> ensureSetupDoing: aBlock [
	
	"Setup ssl only if not already done"
	ssl ifNil: [
		self setUp.
		aBlock value. ].
]

{ #category : #primitives }
ZdcOpenSSLSession >> ffiLibraryName [

	^ 'libssl'
]

{ #category : #primitives }
ZdcOpenSSLSession >> getPeerCertificate [

	^ self ffiCall: #(void* SSL_get_peer_certificate(void* ssl))
]

{ #category : #primitives }
ZdcOpenSSLSession >> getSSLErrorForReturnCode: returnCode [

	^ self ffiCall: #(int SSL_get_error(void* ssl, int returnCode))
]

{ #category : #initialization }
ZdcOpenSSLSession >> initialize [
	super initialize.
	type := SSL_FILETYPE_PEM.
	self validateFullCertificate.
]

{ #category : #testing }
ZdcOpenSSLSession >> isConnected [
	"Returns true if the SSL handshake has been completed"
	"Returns the current state of the SSL connection:
		0 - Unused
		1 - In accept handshake
		2 - In connect handshake
		3 - Connected"
		
	^ state = 3
]

{ #category : #primitives }
ZdcOpenSSLSession >> newSSLContext: aMethod [
	
	^ self ffiCall: #(void *SSL_CTX_new(void* aMethod)) module: 'libssl'
]

{ #category : #primitives }
ZdcOpenSSLSession >> newSSLWithContext: aContext [

	^ self ffiCall: #(void* SSL_new(void* aContext))
]

{ #category : #primitives }
ZdcOpenSSLSession >> newSSLv23Method [
	
	"ExternalAddress loadSymbol: #SSLv23_method module:'libssl'"
	^ self ffiCall: #(void *SSLv23_method(void))
]

{ #category : #primitives }
ZdcOpenSSLSession >> newTSLMethod [
	
	"ExternalAddress loadSymbol: #TLS_method module:'libssl'"
	^ self ffiCall: #(void *TLS_method(void))
]

{ #category : #primitives }
ZdcOpenSSLSession >> primitiveAccept [

	^ self ffiCall: #(int SSL_accept(void* ssl))
]

{ #category : #primitives }
ZdcOpenSSLSession >> primitiveConnect [

	^ self ffiCall: #(int SSL_connect(void* ssl))
]

{ #category : #primitives }
ZdcOpenSSLSession >> primitiveSetAcceptState [

	^ self ffiCall: #(int SSL_set_accept_state(void* ssl))
]

{ #category : #primitives }
ZdcOpenSSLSession >> primitiveSetConnectState [

	^ self ffiCall: #(int SSL_set_connect_state(void* ssl))
]

{ #category : #primitives }
ZdcOpenSSLSession >> primitiveSetHostName: aServerName [
	^ self
		setSSLControlCommand: SSL_CTRL_SET_TLSEXT_HOSTNAME
		larg: TLSEXT_NAMETYPE_host_name
		parg: (aServerName utf8Encoded copyWith: 0)
]

{ #category : #accessing }
ZdcOpenSSLSession >> privateKeyName [

	^ privateKeyName
]

{ #category : #accessing }
ZdcOpenSSLSession >> privateKeyName: aString [
	
	privateKeyName := aString
]

{ #category : #accessing }
ZdcOpenSSLSession >> serverName [
	"Get the Server Name Indication (SNI) property"
	
	^ serverName
]

{ #category : #accessing }
ZdcOpenSSLSession >> serverName: aString [

	serverName := aString
]

{ #category : #state }
ZdcOpenSSLSession >> setAcceptState [

	self primitiveSetAcceptState.
	state := 1.
]

{ #category : #primitives }
ZdcOpenSSLSession >> setBioRead: bioread bioWrite: biowrite toSSL: eseseele [

	^ self ffiCall: #(int SSL_set_bio(void* eseseele, void* bioread, void* biowrite))
]

{ #category : #primitives }
ZdcOpenSSLSession >> setCertificateFileToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_use_certificate_file(void* aContext, String certificateName, int type))
]

{ #category : #state }
ZdcOpenSSLSession >> setConnectState [

	self primitiveSetConnectState.
	state := 2.
]

{ #category : #primitives }
ZdcOpenSSLSession >> setConnectStateToSsl: eseselele [

	^ self ffiCall: #(int SSL_set_connect_state(void* eseselele))
]

{ #category : #state }
ZdcOpenSSLSession >> setConnectedState [

	state := 3
]

{ #category : #primitives }
ZdcOpenSSLSession >> setControlCommand: command larg: argument parg: pargument toContext: aContext [
	self
		ffiCall: #(ulong SSL_CTX_ctrl #(void * aContext , int command , ulong argument, void * pargument))
		module: 'libssl'
]

{ #category : #primitives }
ZdcOpenSSLSession >> setDefaultVerifyPathToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_set_default_verify_paths(void* aContext))
]

{ #category : #primitives }
ZdcOpenSSLSession >> setPrivateKeyFileToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_use_PrivateKey_file(void* aContext, String privateKeyName, int type))
]

{ #category : #validation }
ZdcOpenSSLSession >> setRootCertificateLocation: aPathString [

	aPathString asFileReference isDirectory
		ifTrue: [ self sslLoadVerifyPath: aPathString ]
		ifFalse: [ self sslLoadVerifyFile: aPathString ]
]

{ #category : #primitives }
ZdcOpenSSLSession >> setSSLControlCommand: command larg: argument parg: pargument [
	"SSL_ctrl(s,command,value,(void *)pargument)"

	self ffiCall: #(ulong SSL_ctrl #(void * ssl , int command , ulong argument , void * pargument))
]

{ #category : #setup }
ZdcOpenSSLSession >> setUp [

	method := self newSSLv23Method.
	context := self newSSLContext: method.
	
	"SSLv2 and SSLv3 are deprecated"
	"self setOptions: SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 toContext: context."
	
	certificateName ifNotNil: [
		self setCertificateFileToContext: context ].
	
	privateKeyName ifNotNil: [
		self setPrivateKeyFileToContext: context ].
	
	self assert: (self setDefaultVerifyPathToContext: context) > 0.
	
	ssl := self newSSLWithContext: context.
	
	readBuffer := ZdcMemoryBIO new setAutoClose.
	writeBuffer := ZdcMemoryBIO new setAutoClose.
	self setBioRead: readBuffer handle bioWrite: writeBuffer handle toSSL: ssl.
	
	certificateValidation configureSSLSession: self
]

{ #category : #validations }
ZdcOpenSSLSession >> setValidatePeer [

	self setVerifyMode: SSL_VERIFY_PEER
]

{ #category : #primitives }
ZdcOpenSSLSession >> setVerifyMode: aMode [
	"void SSL_set_verify(SSL *s, int mode, int (*verify_callback)(int, X509_STORE_CTX *));"
	^ self ffiCall: #(void SSL_set_verify(void* ssl, int aMode, 0))
]

{ #category : #validations }
ZdcOpenSSLSession >> sslLoadVerifyFile: aPath [ 
	self ffiCall: #(int SSL_CTX_load_verify_locations(void *context, String aPath, 0))
]

{ #category : #validations }
ZdcOpenSSLSession >> sslLoadVerifyPath: aPath [ 
	self ffiCall: #(int SSL_CTX_load_verify_locations(void *context, 0, String aPath))
]

{ #category : #'reading-writing' }
ZdcOpenSSLSession >> sslReadIntoBuffer: dstBuffer ofSize: bufferSize [
	"Call SSL to decrypt the bytes in its internal buffer and put the result in the destination buffer"
	^ self ffiCall: #(long SSL_read(void* ssl, ByteArray dstBuffer, ulong bufferSize))
]

{ #category : #accessing }
ZdcOpenSSLSession >> sslState [
	"Returns the current state of the SSL connection:
		0 - Unused
		1 - In accept handshake
		2 - In connect handshake
		3 - Connected"
		
	^ state
]

{ #category : #'reading-writing' }
ZdcOpenSSLSession >> sslWriteFromBuffer: srcBuffer ofSize: bufferSize [
	"Call SSL to read the bytes from the source buffer and write them into its internal buffer"
	^ self ffiCall: #(long SSL_write(void* ssl, ByteArray srcBuffer, ulong bufferSize))
]

{ #category : #initialization }
ZdcOpenSSLSession >> validateFullCertificate [

	certificateValidation := OSPlatform current openSSLCertificateValidationStrategy new
]

{ #category : #initialization }
ZdcOpenSSLSession >> validateHasCertificate [

	certificateValidation := ZdcHasCertificateValidation new
]

{ #category : #primitives }
ZdcOpenSSLSession >> verifyCertificate [
	"long SSL_get_verify_result(const SSL *ssl);"
	^ self ffiCall: #(long SSL_get_verify_result(void* ssl))
]

{ #category : #testing }
ZdcOpenSSLSession >> wantsReadMore: aReturnCode [

	^ (self getSSLErrorForReturnCode: aReturnCode) = SSL_ERROR_WANT_READ
]

{ #category : #'reading-writing' }
ZdcOpenSSLSession >> write: srcBuffer from: from to: to intoBio: aBio [
	
	| written |
	
	"Do not write in Bio if no bytes are required"
	to >= from ifFalse: [ ^ self ].
	
	written := aBio write: (srcBuffer copyFrom: from to: to).
	written < to ifTrue: [ self error: 'Wrote less :/' ].
]
