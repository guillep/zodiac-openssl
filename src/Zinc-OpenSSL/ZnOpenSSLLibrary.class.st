Class {
	#name : #ZnOpenSSLLibrary,
	#superclass : #FFILibrary,
	#category : #'Zinc-OpenSSL'
}

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> defaultCertificateFile [

	self ffiCall: #(String X509_get_default_cert_file())
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> getLastErrorCode [

	^ self ffiCall: #(int ERR_get_error())
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> getLastErrorString [

	^ self getLastErrorStringFromErrorCode: self getLastErrorCode buffer: (ByteArray new: 500).
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> getLastErrorStringFromErrorCode: anErrorCode buffer: aBuffer [

	^ self ffiCall: #(char* ERR_error_string(ulong anErrorCode, ByteArray aBuffer))
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> macModuleName [

	^ self moduleName
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> moduleName [

	^ 'libssl'
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> unixModuleName [

	^ self moduleName
]

{ #category : #'accessing platform' }
ZnOpenSSLLibrary >> win32ModuleName [

	^ self moduleName
]
