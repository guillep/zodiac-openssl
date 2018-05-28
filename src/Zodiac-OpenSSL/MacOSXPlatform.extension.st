Extension { #name : #MacOSXPlatform }

{ #category : #'*Zodiac-OpenSSL' }
MacOSXPlatform >> openSSLCertificateValidationStrategy [

	^ ZdcUnixCertificateValidation
]
