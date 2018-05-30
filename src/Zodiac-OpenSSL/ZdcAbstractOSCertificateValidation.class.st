Class {
	#name : #ZdcAbstractOSCertificateValidation,
	#superclass : #ZdcFullCertificateValidation,
	#classVars : [
		'CachedCertificates'
	],
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #cache }
ZdcAbstractOSCertificateValidation class >> cachedCertificates [
	self requiresLoading
		ifTrue: [ CachedCertificates := self storeClass new rootCertificates ].
		
	^ CachedCertificates
]

{ #category : #cache }
ZdcAbstractOSCertificateValidation class >> requiresLoading [
	^ CachedCertificates isNil or: [ CachedCertificates anySatisfy: #isNull ]
]

{ #category : #cache }
ZdcAbstractOSCertificateValidation class >> resetCache [
	CachedCertificates := nil.
]

{ #category : #'store access' }
ZdcAbstractOSCertificateValidation class >> storeClass [
	^ self subclassResponsibility
]

{ #category : #validation }
ZdcAbstractOSCertificateValidation >> cachedCertificates [
	^ self class cachedCertificates
]

{ #category : #validation }
ZdcAbstractOSCertificateValidation >> configureSSLSession: sslSession [

	| rootCertificates store |
	
	store := sslSession x509CertificateStore.
	rootCertificates := self cachedCertificates.
	rootCertificates do: [ :aCert | store addCertificate: aCert ].
	
	super configureSSLSession: sslSession.

]
