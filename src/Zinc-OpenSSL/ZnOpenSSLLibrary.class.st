Class {
	#name : #ZnOpenSSLLibrary,
	#superclass : #FFILibrary,
	#category : #'Zinc-OpenSSL'
}

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
