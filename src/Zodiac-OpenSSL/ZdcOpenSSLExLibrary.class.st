Class {
	#name : #ZdcOpenSSLExLibrary,
	#superclass : #FFILibrary,
	#category : #'Zodiac-OpenSSL-Core'
}

{ #category : #'accessing platform' }
ZdcOpenSSLExLibrary >> initSSL [

	self ffiCall: #(int SSL_library_init())
]

{ #category : #'accessing platform' }
ZdcOpenSSLExLibrary >> macModuleName [

	^ 'libssl'
]

{ #category : #'accessing platform' }
ZdcOpenSSLExLibrary >> unixModuleName [

	^ 'libssl'
]

{ #category : #'accessing platform' }
ZdcOpenSSLExLibrary >> win32ModuleName [

	^ 'ssleay32'
]
