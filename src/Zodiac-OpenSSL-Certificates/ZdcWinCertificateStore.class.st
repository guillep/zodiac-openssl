Class {
	#name : #ZdcWinCertificateStore,
	#superclass : #Object,
	#classVars : [
		'CERT_STORE_PROV_SYSTEM_A',
		'CERT_SYSTEM_STORE_CURRENT_USER'
	],
	#category : #'Zodiac-OpenSSL-Certificates-Store-Win'
}

{ #category : #'class initialization' }
ZdcWinCertificateStore class >> initialize [
	CERT_STORE_PROV_SYSTEM_A := 9.
	CERT_SYSTEM_STORE_CURRENT_USER := 1 << 16.
]

{ #category : #'as yet unclassified' }
ZdcWinCertificateStore >> certificatesFromStoreNamed: storeName [

	| sysStore cert results buffer |
	
	results := OrderedCollection new.
	
	[
		sysStore := self
			openStore: CERT_STORE_PROV_SYSTEM_A
			flags: CERT_SYSTEM_STORE_CURRENT_USER
			parameter: storeName.
		
		sysStore isNull ifTrue: [ self error: 'Unable to open key store ', storeName ].

		cert := ZdcWinCertificateContext fromHandle: ExternalAddress null.
		[(cert := self ffiCertEnumCertificates: cert inStore: sysStore) isNull ] whileFalse: [
			buffer := ByteArray new: cert cbCertEncoded.
			LibC memCopy: cert pbCertEncoded to: buffer size: buffer size.
			results add: (ZdcX509Certificate newEmpty fromDER: buffer; yourself).
		].
		^ results asArray.
	] ensure: [ 
		sysStore isNull ifFalse: [ self closeStore: sysStore ]
	].	
	
	
]

{ #category : #'as yet unclassified' }
ZdcWinCertificateStore >> closeStore: aStore [

	^ self ffiCall: #(bool CertCloseStore(void* aStore, 0))
]

{ #category : #'as yet unclassified' }
ZdcWinCertificateStore >> ffiCertEnumCertificates: cert inStore: sysStore [

	^ self ffiCall: #(ZdcWinCertificateContext* CertEnumCertificatesInStore(void* sysStore, ZdcWinCertificateContext* cert))
]

{ #category : #'library path' }
ZdcWinCertificateStore >> ffiLibraryName [
	^ 'Crypt32.dll'
]

{ #category : #'as yet unclassified' }
ZdcWinCertificateStore >> openStore: storeProvider flags: flags parameter: pvPara [

	^ self ffiCall: #(void* CertOpenStore(ulong storeProvider, 0, 0, ulong flags, String pvPara))
]

{ #category : #'as yet unclassified' }
ZdcWinCertificateStore >> rootCertificates [

	^ (self certificatesFromStoreNamed: 'root') , (self certificatesFromStoreNamed: 'CA')
]
