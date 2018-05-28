Class {
	#name : #ZdcX509CertificateStore,
	#superclass : #FFIOpaqueObject,
	#category : #'Zodiac-OpenSSL-Certificates'
}

{ #category : #'library path' }
ZdcX509CertificateStore class >> ffiLibraryName [

	^ ZdcOpenSSLLibrary
]

{ #category : #adding }
ZdcX509CertificateStore >> addCertificate: aZdcX509Certificate [ 
	
	^ self ffiCall: #(int X509_STORE_add_cert(self, ZdcX509Certificate* aZdcX509Certificate))
]

{ #category : #'library path' }
ZdcX509CertificateStore >> ffiLibraryName [
	^ self class ffiLibraryName
]
