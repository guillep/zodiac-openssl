Extension { #name : #MacOSXPlatform }

{ #category : #'*Zodiac-OpenSSL' }
MacOSXPlatform >> certificationValidationStrategy [

	^ ZdcUnixCertificateValidation
]
