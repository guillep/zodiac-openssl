Class {
	#name : #ZdcBIO,
	#superclass : #FFIOpaqueObject,
	#classVars : [
		'BIO_CLOSE',
		'BIO_CTRL_RESET',
		'BIO_CTRL_SET_CLOSE'
	],
	#category : #'Zinc-OpenSSL'
}

{ #category : #accessing }
ZdcBIO class >> bioAllocationMethod [
	
	self subclassResponsibility
]

{ #category : #'library path' }
ZdcBIO class >> ffiLibraryName [

	^ ZdcOpenSSLLibrary
]

{ #category : #'class initialization' }
ZdcBIO class >> initialize [
	"self initialize"
	BIO_CTRL_RESET := 1.
	BIO_CLOSE := 1.
	BIO_CTRL_SET_CLOSE := 9.
]

{ #category : #'instance creation' }
ZdcBIO class >> new [

	^ self newExternalBio: self bioAllocationMethod
]

{ #category : #'instance creation' }
ZdcBIO class >> newExternalBio: aMethod [

	^ self ffiCall: #(#ZdcBIO* BIO_new (void *aMethod))
]

{ #category : #'initializing/finalizing' }
ZdcBIO >> close [

	^ self ffiCall: #(int BIO_free(#ZdcBIO *self))
]

{ #category : #actions }
ZdcBIO >> control: command value: aValue [

	^ self ffiCall: #(int BIO_ctrl (ZnBIO *self, int command, long aValue, 0))
]

{ #category : #actions }
ZdcBIO >> errorIfZero: retCode [

	retCode = 0
		ifTrue: [ ZdcOpenSSLError signal: self ffiLibraryName getLastErrorString ]
]

{ #category : #'library path' }
ZdcBIO >> ffiLibraryName [

	^ self class ffiLibraryName
]

{ #category : #actions }
ZdcBIO >> pendingBytes [

	^ self ffiCall: #(int BIO_ctrl_pending(ZnBIO *self))
]

{ #category : #'input/output' }
ZdcBIO >> primitiveWrite: aByteArray size: aSize [

	^ self ffiCall: #(int BIO_write (ZnBIO *self, ByteArray aByteArray, int aSize))
]

{ #category : #'input/output' }
ZdcBIO >> readInto: buffer size: aSize [

	^ self ffiCall: #(int BIO_read(ZnBIO *self, void *buffer, int aSize))
]

{ #category : #actions }
ZdcBIO >> reset [
	
	self errorIfZero: (self control: BIO_CTRL_RESET value: 0)
]

{ #category : #actions }
ZdcBIO >> setAutoClose [

	self errorIfZero: (self control: BIO_CTRL_SET_CLOSE value: BIO_CLOSE)
]

{ #category : #'input/output' }
ZdcBIO >> write: aByteArray [
	
	^ self primitiveWrite: aByteArray size: aByteArray size
]
