Class {
	#name : #ZdcOSXCertificateValidation,
	#superclass : #ZdcAbstractOSCertificateValidation,
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #'store access' }
ZdcOSXCertificateValidation class >> storeClass [
	^ ZdcOSXCertificateStore
]
