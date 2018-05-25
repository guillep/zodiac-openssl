Class {
	#name : #ZdcOpenSSLLibrary,
	#superclass : #FFILibrary,
	#category : #'Zodiac-OpenSSL-Core'
}

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> defaultCertificateFile [

	self ffiCall: #(String X509_get_default_cert_file())
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> getLastErrorCode [

	^ self ffiCall: #(int ERR_get_error())
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

	^ self moduleName
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> moduleName [

	^ 'libssl'
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> unixModuleName [

	^ self moduleName
]

{ #category : #'accessing platform' }
ZdcOpenSSLLibrary >> win32ModuleName [

	^ self moduleName
]
