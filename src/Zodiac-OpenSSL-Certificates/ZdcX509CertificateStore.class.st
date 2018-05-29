"
I represent a X509 certificate store in openSSL.

I am an opaque external object. 
I should be used through the functions exposed in OpenSSL.

If you keep a reference to me take care that I am nulled when the image is closed. 
So maybe you don't want to keep a reference to me.

I am only created by the OpenSSL functions. 
I can add certificates to the underlying openssl object.
"
Class {
	#name : #ZdcX509CertificateStore,
	#superclass : #FFIOpaqueObject,
	#category : #'Zodiac-OpenSSL-Certificates-Base'
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
