Class {
	#name : #ZdcFullCertificateValidation,
	#superclass : #Object,
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #validation }
ZdcFullCertificateValidation >> configureSSLSession: sslSession [
	sslSession setValidatePeer
]

{ #category : #validation }
ZdcFullCertificateValidation >> validateCertificate: sslSession [
	
	sslSession verifyCertificate = sslSession class X509_V_OK
		ifFalse: [ self error: 'Invalid certificate' ].
]
