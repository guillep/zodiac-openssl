Class {
	#name : #ZnBIO,
	#superclass : #FFIOpaqueObject,
	#classVars : [
		'BIO_CLOSE',
		'BIO_CTRL_RESET',
		'BIO_CTRL_SET_CLOSE'
	],
	#category : #'Zinc-OpenSSL'
}

{ #category : #accessing }
ZnBIO class >> bioAllocationMethod [
	
	self subclassResponsibility
]

{ #category : #'library path' }
ZnBIO class >> ffiLibraryName [

	^ ZnOpenSSLLibrary
]

{ #category : #'class initialization' }
ZnBIO class >> initialize [
	"self initialize"
	BIO_CTRL_RESET := 1.
	BIO_CLOSE := 1.
	BIO_CTRL_SET_CLOSE := 9.
]

{ #category : #'instance creation' }
ZnBIO class >> new [

	^ self newExternalBio: self bioAllocationMethod
]

{ #category : #'instance creation' }
ZnBIO class >> newExternalBio: aMethod [

	^ self ffiCall: #(ZnBIO* BIO_new (void *aMethod))
]

{ #category : #'initializing/finalizing' }
ZnBIO >> close [

	^ self ffiCall: #(int BIO_free(ZnBIO *self))
]

{ #category : #actions }
ZnBIO >> control: command value: aValue [

	^ self ffiCall: #(int BIO_ctrl (ZnBIO *self, int command, long aValue, 0))
]

{ #category : #actions }
ZnBIO >> errorIfZero: retCode [

	retCode = 0
		ifTrue: [ ZnOpenSSLError signal: self library getLastErrorString ]
]

{ #category : #'library path' }
ZnBIO >> ffiLibraryName [

	^ self class ffiLibraryName
]

{ #category : #actions }
ZnBIO >> pendingBytes [

	^ self ffiCall: #(int BIO_ctrl_pending(ZnBIO *self))
]

{ #category : #'input/output' }
ZnBIO >> primitiveWrite: aByteArray size: aSize [

	^ self ffiCall: #(int BIO_write (ZnBIO *self, ByteArray aByteArray, int aSize))
]

{ #category : #'input/output' }
ZnBIO >> readInto: buffer size: aSize [

	^ self ffiCall: #(int BIO_read(ZnBIO *self, void *buffer, int aSize))
]

{ #category : #actions }
ZnBIO >> reset [
	
	self errorIfZero: (self control: BIO_CTRL_RESET value: 0)
]

{ #category : #actions }
ZnBIO >> setAutoClose [

	self errorIfZero: (self control: BIO_CTRL_SET_CLOSE value: BIO_CLOSE)
]

{ #category : #'input/output' }
ZnBIO >> write: aByteArray [
	
	^ self primitiveWrite: aByteArray size: aByteArray size
]
