"
I represent the CERT_CONTEXT structure, used in Windows Certificate Store calls.

The CERT_CONTEXT structure contains both the encoded and decoded representations of a certificate. 
A certificate context returned by one of the functions defined in Wincrypt.h must be freed by calling the CertFreeCertificateContext function. 
The CertDuplicateCertificateContext function can be called to make a duplicate copy (which also must be freed by calling CertFreeCertificateContext).

https://msdn.microsoft.com/en-us/library/windows/desktop/aa377189(v=vs.85).aspx
"
Class {
	#name : #ZdcWinCertificateContext,
	#superclass : #FFIExternalStructure,
	#classVars : [
		'OFFSET_CBCERTENCODED',
		'OFFSET_DWCERTENCODINGTYPE',
		'OFFSET_HCERTSTORE',
		'OFFSET_PBCERTENCODED',
		'OFFSET_PCERTINFO'
	],
	#category : #'Zodiac-OpenSSL-Certificates-Store-Win'
}

{ #category : #'field definition' }
ZdcWinCertificateContext class >> fieldsDesc [

	" self rebuildFieldAccessors "

	^ #(
	 ulong 		dwCertEncodingType;
    byte 			*pbCertEncoded;
    ulong     	cbCertEncoded;
    void*		 	pCertInfo
    void*			hCertStore)
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> cbCertEncoded [
	"This method was automatically generated"
	^handle platformUnsignedLongAt: OFFSET_CBCERTENCODED
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> cbCertEncoded: anObject [
	"This method was automatically generated"
	^handle platformUnsignedLongAt: OFFSET_CBCERTENCODED put: anObject
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> dwCertEncodingType [
	"This method was automatically generated"
	^handle platformUnsignedLongAt: OFFSET_DWCERTENCODINGTYPE
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> dwCertEncodingType: anObject [
	"This method was automatically generated"
	^handle platformUnsignedLongAt: OFFSET_DWCERTENCODINGTYPE put: anObject
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> hCertStore [
	"This method was automatically generated"
	^ExternalData fromHandle: (handle pointerAt: OFFSET_HCERTSTORE) type: ExternalType void asPointerType
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> hCertStore: anObject [
	"This method was automatically generated"
	handle pointerAt: OFFSET_HCERTSTORE put: anObject getHandle.
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> pCertInfo [
	"This method was automatically generated"
	^ExternalData fromHandle: (handle pointerAt: OFFSET_PCERTINFO) type: ExternalType void asPointerType
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> pCertInfo: anObject [
	"This method was automatically generated"
	handle pointerAt: OFFSET_PCERTINFO put: anObject getHandle.
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> pbCertEncoded [
	"This method was automatically generated"
	^ExternalData fromHandle: (handle pointerAt: OFFSET_PBCERTENCODED) type: ExternalType byte asPointerType
]

{ #category : #'accessing structure variables' }
ZdcWinCertificateContext >> pbCertEncoded: anObject [
	"This method was automatically generated"
	handle pointerAt: OFFSET_PBCERTENCODED put: anObject getHandle.
]
