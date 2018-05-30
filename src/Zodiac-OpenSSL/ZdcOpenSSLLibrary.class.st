Class {
	#name : #ZdcOpenSSLLibrary,
	#superclass : #FFILibrary,
	#category : #'Zodiac-OpenSSL-Core'
}

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> defaultCertificateFile [

	self ffiCall: #(String X509_get_default_cert_file())
]

{ #category : #errors }
ZdcOpenSSLLibrary >> getErrorFunction: anErrorCode [ 

	"# define ERR_GET_FUNC(l)         (int)(((l) >> 12L) & 0xFFFL)"
	^ anErrorCode >> 12 & 16rFFF
]

{ #category : #errors }
ZdcOpenSSLLibrary >> getErrorLib: anErrorCode [ 

	"# define ERR_GET_LIB(l)          (int)(((l) >> 24L) & 0x0FFL)"
	^ anErrorCode >> 24 & 16rFF
]

{ #category : #errors }
ZdcOpenSSLLibrary >> getErrorReason: anErrorCode [ 

	"# define ERR_GET_REASON(l)       (int)( (l)         & 0xFFFL)"
	^ anErrorCode & 16rFFF
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> getLastErrorCode [

	^ self ffiCall: #(ulong ERR_get_error())
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> getLastErrorString [

	^ self getLastErrorStringFromErrorCode: self getLastErrorCode buffer: (ByteArray new: 500).
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> getLastErrorStringFromErrorCode: anErrorCode buffer: aBuffer [

	^ self ffiCall: #(char* ERR_error_string(ulong anErrorCode, ByteArray aBuffer))
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> macModuleName [

	^ 'libssl'
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> unixModuleName [

	^ 'libssl'
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> win32ModuleName [

	^ 'libeay32'
]
