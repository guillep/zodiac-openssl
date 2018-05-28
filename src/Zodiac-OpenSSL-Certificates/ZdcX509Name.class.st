Class {
	#name : #ZdcX509Name,
	#superclass : #FFIOpaqueObject,
	#classVars : [
		'ASN1_STRFLGS_ESC_CTRL',
		'ASN1_STRFLGS_ESC_MSB',
		'XN_FLAG_FN_ALIGN',
		'XN_FLAG_FN_LN',
		'XN_FLAG_MULTILINE',
		'XN_FLAG_SEP_MULTILINE',
		'XN_FLAG_SPC_EQ'
	],
	#category : #'Zodiac-OpenSSL-Certificates'
}

{ #category : #resources }
ZdcX509Name class >> ffiLibraryName [

	^ ZdcOpenSSLLibrary
]

{ #category : #'class initialization' }
ZdcX509Name class >> initialize [
	ASN1_STRFLGS_ESC_CTRL := 2.
	ASN1_STRFLGS_ESC_MSB := 4.
	
	XN_FLAG_SEP_MULTILINE := 4 << 16.
	XN_FLAG_FN_LN := 1 << 21.
	XN_FLAG_SPC_EQ := 1 << 23.
	XN_FLAG_FN_ALIGN := 1 << 25.
	
	XN_FLAG_MULTILINE := ASN1_STRFLGS_ESC_CTRL | ASN1_STRFLGS_ESC_MSB | XN_FLAG_SEP_MULTILINE
		| XN_FLAG_SPC_EQ | XN_FLAG_FN_LN | XN_FLAG_FN_ALIGN
]

{ #category : #resources }
ZdcX509Name >> ffiLibraryName [
	^ self class ffiLibraryName
]

{ #category : #'ffi-calls' }
ZdcX509Name >> ffiPrintExInto: bio format: flags [

	self ffiCall: #(int X509_NAME_print_ex(ZdcBIO *bio, self, 0, ulong flags))
]

{ #category : #'ffi-calls' }
ZdcX509Name >> ffiPrintInto: bio. [

	self ffiCall: #(int X509_NAME_print(ZdcBIO *bio, self, 0))	
]

{ #category : #'string representations' }
ZdcX509Name >> fullString [
	| bio returnCode buffer |

	bio := ZdcMemoryBIO new
		setAutoClose;
		autoRelease;
		yourself.
		
	returnCode := self ffiPrintExInto: bio format: XN_FLAG_MULTILINE.

	returnCode < 0 ifTrue: [ self error: 'Error while printing name: ' , returnCode printString ].
	
	buffer := ByteArray new: bio pendingBytes.
	bio readInto: buffer size: buffer size.
	
	^ buffer utf8Decoded.
]

{ #category : #'string representations' }
ZdcX509Name >> nameString [
	| bio returnCode buffer |

	bio := ZdcMemoryBIO new
		setAutoClose;
		autoRelease;
		yourself.
		
	returnCode := self ffiPrintInto: bio.

	returnCode ~= 1 ifTrue: [ self error: 'Error while printing name: ' , returnCode printString ].
	
	buffer := ByteArray new: bio pendingBytes.
	bio readInto: buffer size: buffer size.
	
	^ buffer utf8Decoded.
]
