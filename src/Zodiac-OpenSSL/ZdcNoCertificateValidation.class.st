Class {
	#name : #ZdcNoCertificateValidation,
	#superclass : #Object,
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #validation }
ZdcNoCertificateValidation >> configureSSLSession: sslSession [
]

{ #category : #validation }
ZdcNoCertificateValidation >> validateCertificate: sslSession [

	"Do Nothing"
]
