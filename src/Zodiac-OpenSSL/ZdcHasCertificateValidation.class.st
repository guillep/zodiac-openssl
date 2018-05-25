Class {
	#name : #ZdcHasCertificateValidation,
	#superclass : #Object,
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #validation }
ZdcHasCertificateValidation >> validateCertificate: sslSession [

	self assert: sslSession getPeerCertificate notNil
]
