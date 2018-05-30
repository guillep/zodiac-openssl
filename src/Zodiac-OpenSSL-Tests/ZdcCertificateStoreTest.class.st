Class {
	#name : #ZdcCertificateStoreTest,
	#superclass : #TestCase,
	#instVars : [
		'ssl'
	],
	#category : #'Zodiac-OpenSSL-Tests'
}

{ #category : #tests }
ZdcCertificateStoreTest >> newDuplicatingCertificateValidation [

	| aClass |
	aClass := Object newAnonymousSubclass.
	aClass addSlot: #certificateValidation.
	aClass compile: 'certificateValidation: aValue
	certificateValidation := aValue'.
	
	aClass compile: 'configureSSLSession: sslSession
		"I call it twice, it should handle it correctly"
		certificateValidation configureSSLSession: sslSession.
		certificateValidation configureSSLSession: sslSession.
	'.

	^ aClass new
]

{ #category : #running }
ZdcCertificateStoreTest >> setUp [
	super setUp.
	ssl := ZdcOpenSSLSession new.
	
]

{ #category : #running }
ZdcCertificateStoreTest >> tearDown [
	ssl ifNotNil: #destroy.
	super tearDown.
	
	
]

{ #category : #tests }
ZdcCertificateStoreTest >> testAddingDuplicateCertificate [

	| certificateValidationMock |
			
	certificateValidationMock := self newDuplicatingCertificateValidation.
	certificateValidationMock certificateValidation: ssl certificateValidation.
	
	ssl certificateValidation: certificateValidationMock.
	ssl setUp
]
