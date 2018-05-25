Class {
	#name : #ZdcFullCertificateValidation,
	#superclass : #Object,
	#category : #'Zinc-OpenSSL-CertificateValidations'
}

{ #category : #validation }
ZdcFullCertificateValidation >> validateCertificate: sslSession [

	sslSession setValidatePeer.
	sslSession verifyCertificate = sslSession  X509_V_OK
		ifFalse: [ self error: 'Invalid certificate' ].
]
