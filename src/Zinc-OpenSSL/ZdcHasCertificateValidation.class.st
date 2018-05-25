Class {
	#name : #ZdcHasCertificateValidation,
	#superclass : #Object,
	#category : #'Zinc-OpenSSL-CertificateValidations'
}

{ #category : #validation }
ZdcHasCertificateValidation >> validateCertificate: sslSession [

	self assert: sslSession getPeerCertificate notNil
]
