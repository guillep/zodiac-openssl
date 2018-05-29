"
I implement the access to the Windows operating system certificate store.

I should be used calling #rootCertificate that returns ZdcX509Certificates
"
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
	
		"I create a null certificate to send as first request. Subsequent request are called with the previous value."
		cert := ZdcWinCertificateContext fromHandle: ExternalAddress null.
		
		[(cert := self ffiCertEnumCertificates: cert inStore: sysStore) isNull ] whileFalse: [
			buffer := ByteArray new: cert cbCertEncoded.
			LibC memCopy: cert pbCertEncoded to: buffer size: buffer size.
			results add: (ZdcX509Certificate newFromDER: buffer).
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

	"The CertEnumCertificatesInStore function retrieves the first or next certificate in a certificate store. 
	Used in a loop, this function can retrieve in sequence all certificates in a certificate store.
	
	If the function succeeds, the function returns a pointer to the next CERT_CONTEXT in the store. If no more certificates exist in the store, the function returns NULL.
	The returned pointer is freed when passed as the pPrevCertContext parameter on a subsequent call. 
	Otherwise, the pointer must be freed by calling CertFreeCertificateContext. A non-NULL pPrevCertContext passed to CertEnumCertificatesInStore is always freed even for an error.
	
	Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376050(v=vs.85).aspx
	"
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
