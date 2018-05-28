Class {
	#name : #ZdcX509Certificate,
	#superclass : #FFIOpaqueObject,
	#classVars : [
		'X509_PTR'
	],
	#category : #'Zodiac-OpenSSL-Certificates'
}

{ #category : #resources }
ZdcX509Certificate class >> ffiLibraryName [

	^ ZdcOpenSSLLibrary
]

{ #category : #'ffi-calls' }
ZdcX509Certificate class >> ffiNewX509 [
	
	self ffiCall: 'void * X509_new(void);'
]

{ #category : #finalization }
ZdcX509Certificate class >> finalizeResourceData: handle [
	handle isNull ifTrue: [ ^ self ].
	self freeX509: handle.
	handle beNull
]

{ #category : #finalization }
ZdcX509Certificate class >> freeX509: aHandle [

	self ffiCall: #(void X509_free(void *aHandle))
]

{ #category : #finalization }
ZdcX509Certificate class >> initialize [
	
	X509_PTR := FFIExternalValueHolder ofType: 'ZdcX509Certificate*'. 
]

{ #category : #finalization }
ZdcX509Certificate class >> newEmpty [
	^ (self fromHandle: self ffiNewX509)
		autoRelease;
		yourself
]

{ #category : #'ffi - encoding / decoding' }
ZdcX509Certificate >> decodeFrom: bio intoHolder: ptr [

	^ self ffiCall: #(void* d2i_X509_bio(ZdcBIO *bio, X509_PTR ptr))
]

{ #category : #'encoding / decoding' }
ZdcX509Certificate >> derFormat [

	| bio returnCode buffer |
	bio := ZdcMemoryBIO new
		setAutoClose;
		autoRelease;
		yourself.

	returnCode := self encodeInto: bio.

	returnCode < 0
		ifTrue: [ self error: 'Error encoding the certificate in DER format:' , returnCode printString ].
		
	buffer := ByteArray new: bio pendingBytes.
	bio readInto: buffer size: buffer size.
	
	^ buffer.
]

{ #category : #'ffi - encoding / decoding' }
ZdcX509Certificate >> encodeInto: bio [

	^ self ffiCall: #(int i2d_X509_bio(ZdcBIO *bio, self))
]

{ #category : #resources }
ZdcX509Certificate >> ffiLibraryName [
	^ self class ffiLibraryName
]

{ #category : #'ffi - encoding / decoding' }
ZdcX509Certificate >> ffiPEMReadFrom: bio holder: ptr [

	self ffiCall: #(void* PEM_read_bio_X509(ZdcBIO *bio, X509_PTR ptr, 0, 0))
]

{ #category : #'encoding / decoding' }
ZdcX509Certificate >> fromDER: buffer [

	| bio returnCode ptr |

	bio := ZdcMemoryBIO new
		setAutoClose;
		autoRelease;
		yourself.
		
	returnCode := bio write: buffer.
	
	returnCode < buffer size ifTrue: [ self error: 'Error while writing in the Openssl buffer:' , returnCode printString ].
	
	ptr := X509_PTR new.
	ptr value: self handle getHandle.

	returnCode := self decodeFrom: bio intoHolder: ptr.
		
	returnCode isNull ifTrue: [ self error: 'Error reading the DER' ].
	

]

{ #category : #'encoding / decoding' }
ZdcX509Certificate >> fromPEM: aString [

	| bio buffer returnCode ptr |

	buffer := aString utf8Encoded.

	bio := ZdcMemoryBIO new
		setAutoClose;
		autoRelease;
		yourself.
		
	returnCode := bio write: buffer.
	
	returnCode < buffer size ifTrue: [ self error: 'Error while writing in the Openssl buffer:' , returnCode printString ].
	
	ptr := X509_PTR new.
	ptr value: self handle getHandle.

	returnCode := self ffiPEMReadFrom: bio holder: ptr.
	
	returnCode isNull ifTrue: [ self error: 'Error reading the PEM' ].
	

]

{ #category : #'ffi - accessing' }
ZdcX509Certificate >> issuerName [ 
	"X509_get_subject_name() returns the issuer name of certificate. The returned value is an internal pointer which MUST NOT be freed."
	^ self ffiCall: #(ZdcX509Name* X509_get_issuer_name(self))
]

{ #category : #accessing }
ZdcX509Certificate >> name [
	^ self subjectName nameString.
]

{ #category : #'encoding / decoding' }
ZdcX509Certificate >> pemFormat [

	| bio returnCode buffer |
	bio := ZdcMemoryBIO new
		setAutoClose;
		autoRelease;
		yourself.

	returnCode := self writePEMInto: bio.

	returnCode < 0
		ifTrue: [ self error: 'Error encoding the certificate in PEM format:' , returnCode printString ].
		
	buffer := ByteArray new: bio pendingBytes.
	bio readInto: buffer size: buffer size.
	
	^ buffer utf8Decoded.
]

{ #category : #'ffi - encoding / decoding' }
ZdcX509Certificate >> printOn: aStream [
	
	super printOn: aStream.
	
	handle isNull ifTrue: [ ^self ].

	aStream 
		nextPutAll: '(';
		nextPutAll: self name;
		nextPutAll: ')'.
]

{ #category : #'ffi - accessing' }
ZdcX509Certificate >> subjectName [ 
	"X509_get_subject_name() returns the subject name of certificate. The returned value is an internal pointer which MUST NOT be freed."
	^ self ffiCall: #(ZdcX509Name* X509_get_subject_name(self))
]

{ #category : #'ffi - encoding / decoding' }
ZdcX509Certificate >> writePEMInto: bio [

	^ self ffiCall: #(int PEM_write_bio_X509(ZdcBIO *bio, self))
]
