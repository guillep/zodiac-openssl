Class {
	#name : #ZdcWinCertificateValidation,
	#superclass : #ZdcAbstractOSCertificateValidation,
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #'store access' }
ZdcWinCertificateValidation class >> storeClass [
	^ ZdcWinCertificateStore 
]
