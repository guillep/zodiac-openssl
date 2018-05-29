"
I am the FFILibrary for the Security framework in OSX
"
Class {
	#name : #ZdcOSXSecurityLibrary,
	#superclass : #FFILibrary,
	#category : #'Zodiac-OpenSSL-Certificates-Stores-OSX'
}

{ #category : #'accessing platform' }
ZdcOSXSecurityLibrary >> macModuleName [ 
	
	^ 'Security'
]

{ #category : #'as yet unclassified' }
ZdcOSXSecurityLibrary >> releaseHandle: aHandle [

	^ self ffiCall: #(void CFRelease(void* aHandle))
]
