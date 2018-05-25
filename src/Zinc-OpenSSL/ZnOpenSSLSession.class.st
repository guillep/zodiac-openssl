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
		'state',
		'privateKeyName'
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
	#category : #'Zinc-OpenSSL'
}

{ #category : #installation }
ZnOpenSSLSession class >> ensureZincPluggableSession [

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
ZnOpenSSLSession class >> initialize [
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
ZnOpenSSLSession class >> install [
	<script>
	"self install"
	self ensureZincPluggableSession.
	ZnNetworkingUtils default sslSessionClass: self.
]

{ #category : #operations }
ZnOpenSSLSession >> accept: srcBuffer from: start to: stop into: dstBuffer [ 
	| acceptResult |

	self ensureSetupDoing: [ self setAcceptState ].
	self write: srcBuffer from: start to: stop intoBio: readBuffer.
	
	"If an error occurred, it may have happened that SSL wants to read more bytes.
	In that case, we continue, otherwise we fail with a -1"
	acceptResult := self primitiveAccept.
	(acceptResult < 0 and: [ self wantsReadMore: acceptResult ])
		ifTrue: [ ^ -1 ].

	state := 3.
	^ writeBuffer readInto: dstBuffer size: dstBuffer size
]

{ #category : #accessing }
ZnOpenSSLSession >> certificateName [
	"The name of the local certificate to provide to the remote peer"

	^ certificateName
]

{ #category : #accessing }
ZnOpenSSLSession >> certificateName: aString [
	
	certificateName := aString
]

{ #category : #operations }
ZnOpenSSLSession >> connect: srcBuffer from: start to: stop into: dstBuffer [
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

	state := 3.
	self setVerifyMode: SSL_VERIFY_PEER.
	self getPeerCertificate.
	"self verifyCertificate = X509_V_OK
		ifFalse: [ self error: 'Invalid certificate' ]."
	^ 0
]

{ #category : #operations }
ZnOpenSSLSession >> decrypt: srcBuffer from: start to: stop into: dstBuffer [ 

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
ZnOpenSSLSession >> destroy [
	
	"WHAT?"
]

{ #category : #accessing }
ZnOpenSSLSession >> enableLogging [

	
]

{ #category : #operations }
ZnOpenSSLSession >> encrypt: srcBuffer from: start to: stop into: dstBuffer [ 
	
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
ZnOpenSSLSession >> ensureSetupDoing: aBlock [
	
	"Setup ssl only if not already done"
	ssl ifNil: [
		self setUp.
		aBlock value. ].
]

{ #category : #primitives }
ZnOpenSSLSession >> ffiLibraryName [

	^ 'libssl'
]

{ #category : #primitives }
ZnOpenSSLSession >> getPeerCertificate [

	^ self ffiCall: #(void* SSL_get_peer_certificate(void* ssl))
]

{ #category : #primitives }
ZnOpenSSLSession >> getSSLErrorForReturnCode: returnCode [

	^ self ffiCall: #(int SSL_get_error(void* ssl, int returnCode))
]

{ #category : #initialization }
ZnOpenSSLSession >> initialize [
	super initialize.
	type := SSL_FILETYPE_PEM.
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

{ #category : #primitives }
ZnOpenSSLSession >> newSSLContext: aMethod [
	
	^ self ffiCall: #(void *SSL_CTX_new(void* aMethod)) module: 'libssl'
]

{ #category : #primitives }
ZnOpenSSLSession >> newSSLWithContext: aContext [

	^ self ffiCall: #(void* SSL_new(void* aContext))
]

{ #category : #primitives }
ZnOpenSSLSession >> newSSLv23Method [
	
	"ExternalAddress loadSymbol: #SSLv23_method module:'libssl'"
	^ self ffiCall: #(void *SSLv23_method(void))
]

{ #category : #primitives }
ZnOpenSSLSession >> newTSLMethod [
	
	"ExternalAddress loadSymbol: #TLS_method module:'libssl'"
	^ self ffiCall: #(void *TLS_method(void))
]

{ #category : #primitives }
ZnOpenSSLSession >> primitiveAccept [

	^ self ffiCall: #(int SSL_accept(void* ssl))
]

{ #category : #primitives }
ZnOpenSSLSession >> primitiveConnect [

	^ self ffiCall: #(int SSL_connect(void* ssl))
]

{ #category : #primitives }
ZnOpenSSLSession >> primitiveSetAcceptState [

	^ self ffiCall: #(int SSL_set_accept_state(void* ssl))
]

{ #category : #primitives }
ZnOpenSSLSession >> primitiveSetConnectState [

	^ self ffiCall: #(int SSL_set_connect_state(void* ssl))
]

{ #category : #primitives }
ZnOpenSSLSession >> primitiveSetHostName: aServerName [
	^ self
		setSSLControlCommand: SSL_CTRL_SET_TLSEXT_HOSTNAME
		larg: TLSEXT_NAMETYPE_host_name
		parg: (aServerName utf8Encoded copyWith: 0)
]

{ #category : #accessing }
ZnOpenSSLSession >> privateKeyName [

	^ privateKeyName
]

{ #category : #accessing }
ZnOpenSSLSession >> privateKeyName: aString [
	
	privateKeyName := aString
]

{ #category : #accessing }
ZnOpenSSLSession >> serverName [
	"Get the Server Name Indication (SNI) property"
	
	^ serverName
]

{ #category : #accessing }
ZnOpenSSLSession >> serverName: aString [

	serverName := aString
]

{ #category : #state }
ZnOpenSSLSession >> setAcceptState [

	self primitiveSetAcceptState.
	state := 1.
]

{ #category : #primitives }
ZnOpenSSLSession >> setBioRead: bioread bioWrite: biowrite toSSL: eseseele [

	^ self ffiCall: #(int SSL_set_bio(void* eseseele, void* bioread, void* biowrite))
]

{ #category : #primitives }
ZnOpenSSLSession >> setCertificateFileToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_use_certificate_file(void* aContext, String certificateName, int type))
]

{ #category : #state }
ZnOpenSSLSession >> setConnectState [

	self primitiveSetConnectState.
	state := 2.
]

{ #category : #primitives }
ZnOpenSSLSession >> setConnectStateToSsl: eseselele [

	^ self ffiCall: #(int SSL_set_connect_state(void* eseselele))
]

{ #category : #primitives }
ZnOpenSSLSession >> setControlCommand: command larg: argument parg: pargument toContext: aContext [
	self
		ffiCall: #(ulong SSL_CTX_ctrl #(void * aContext , int command , ulong argument, void * pargument))
		module: 'libssl'
]

{ #category : #primitives }
ZnOpenSSLSession >> setDefaultVerifyPathToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_set_default_verify_paths(void* aContext))
]

{ #category : #primitives }
ZnOpenSSLSession >> setPrivateKeyFileToContext: aContext [

	^ self ffiCall: #(int SSL_CTX_use_PrivateKey_file(void* aContext, String privateKeyName, int type))
]

{ #category : #primitives }
ZnOpenSSLSession >> setSSLControlCommand: command larg: argument parg: pargument [
	"SSL_ctrl(s,command,value,(void *)pargument)"

	self ffiCall: #(ulong SSL_ctrl #(void * ssl , int command , ulong argument , void * pargument))
]

{ #category : #setup }
ZnOpenSSLSession >> setUp [

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
	
	readBuffer := ZnMemoryBIO new setAutoClose.
	writeBuffer := ZnMemoryBIO new setAutoClose.
	self setBioRead: readBuffer handle bioWrite: writeBuffer handle toSSL: ssl.
]

{ #category : #primitives }
ZnOpenSSLSession >> setVerifyMode: aMode [
	"void SSL_set_verify(SSL *s, int mode, int (*verify_callback)(int, X509_STORE_CTX *));"
	^ self ffiCall: #(void SSL_set_verify(void* ssl, int aMode, 0))
]

{ #category : #'reading-writing' }
ZnOpenSSLSession >> sslReadIntoBuffer: dstBuffer ofSize: bufferSize [
	"Call SSL to decrypt the bytes in its internal buffer and put the result in the destination buffer"
	^ self ffiCall: #(long SSL_read(void* ssl, ByteArray dstBuffer, ulong bufferSize))
]

{ #category : #accessing }
ZnOpenSSLSession >> sslState [
	"Returns the current state of the SSL connection:
		0 - Unused
		1 - In accept handshake
		2 - In connect handshake
		3 - Connected"
		
	^ state
]

{ #category : #'reading-writing' }
ZnOpenSSLSession >> sslWriteFromBuffer: srcBuffer ofSize: bufferSize [
	"Call SSL to read the bytes from the source buffer and write them into its internal buffer"
	^ self ffiCall: #(long SSL_write(void* ssl, ByteArray srcBuffer, ulong bufferSize))
]

{ #category : #primitives }
ZnOpenSSLSession >> verifyCertificate [
	"long SSL_get_verify_result(const SSL *ssl);"
	^ self ffiCall: #(long SSL_get_verify_result(void* ssl))
]

{ #category : #testing }
ZnOpenSSLSession >> wantsReadMore: aReturnCode [

	^ (self getSSLErrorForReturnCode: aReturnCode) = SSL_ERROR_WANT_READ
]

{ #category : #'reading-writing' }
ZnOpenSSLSession >> write: srcBuffer from: from to: to intoBio: aBio [
	
	| written |
	
	"Do not write in Bio if no bytes are required"
	to >= from ifFalse: [ ^ self ].
	
	written := aBio write: (srcBuffer copyFrom: from to: to).
	written < to ifTrue: [ self error: 'Wrote less :/' ].
]
