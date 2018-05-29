"
I implement the access to the OSX operating system certificate store.

I should be used calling #rootCertificate that returns ZdcX509Certificates
"
Class {
	#name : #ZdcOSXCertificateStore,
	#superclass : #Object,
	#classVars : [
		'CFArrayRef_PTR',
		'OSStatus'
	],
	#category : #'Zodiac-OpenSSL-Certificates-Stores-OSX'
}

{ #category : #'library path' }
ZdcOSXCertificateStore class >> ffiLibraryName [
	^ ZdcOSXSecurityLibrary
]

{ #category : #'library path' }
ZdcOSXCertificateStore class >> initialize [
	
	OSStatus := #int32.
	CFArrayRef_PTR := FFIExternalValueHolder ofType: 'ZdcCFArrayRef'.
]

{ #category : #'as yet unclassified' }
ZdcOSXCertificateStore >> collectX509: aCFArray [
	| result |
	
	result := Array new: aCFArray size.
	0 to: (aCFArray size - 1) do: [ :index | result at: (index + 1) put: (self toX509: (aCFArray at: index)) ].
	
	^ result.
]

{ #category : #'ffi-calls' }
ZdcOSXCertificateStore >> ffiCFDataGetBytePtr: aPtr [ 
	
	^ self ffiCall: #(void* CFDataGetBytePtr(void* aPtr))
]

{ #category : #'ffi-calls' }
ZdcOSXCertificateStore >> ffiCFDataGetLength: aPtr [ 
	
	^ self ffiCall: #(long CFDataGetLength(void* aPtr))
]

{ #category : #'ffi-calls' }
ZdcOSXCertificateStore >> ffiCopyAnchorCertificatesInto: anchors [

	^ self ffiCall: #(OSStatus SecTrustCopyAnchorCertificates(CFArrayRef_PTR anchors))
]

{ #category : #'as yet unclassified' }
ZdcOSXCertificateStore >> ffiLibraryName [
	^ self class ffiLibraryName
]

{ #category : #'ffi-calls' }
ZdcOSXCertificateStore >> ffiSecCertificateCopyData: aPtr [

	^ self ffiCall: #(void* SecCertificateCopyData(void* aPtr))
]

{ #category : #'as yet unclassified' }
ZdcOSXCertificateStore >> rootCertificates [

	| osStatus result array |
	
	result := CFArrayRef_PTR new.
	osStatus := self ffiCopyAnchorCertificatesInto: result.
	
	osStatus ~= 0 ifTrue: [ self error: 'Error retrieving anchor certificates from OS' ].
	
	array := result value.
	array autoRelease.
	
	^ self collectX509: array
]

{ #category : #conversion }
ZdcOSXCertificateStore >> toX509: ptrToSecCertificateRef [
	| certData rawData length buffer |

	[ 
		certData := self ffiSecCertificateCopyData: ptrToSecCertificateRef.
		certData isNull
			ifTrue: [ self error: 'Error extracting data from certificate' ].

		rawData := self ffiCFDataGetBytePtr: certData.
		length := self ffiCFDataGetLength: certData.
		buffer := ByteArray new: length.

		LibC uniqueInstance memCopy: rawData to: buffer size: length.

		^ ZdcX509Certificate newFromDER: buffer.
	] ensure: [ 
		certData isNull
				ifFalse: [ ZdcOSXSecurityLibrary uniqueInstance releaseHandle: certData ].
	]
]
