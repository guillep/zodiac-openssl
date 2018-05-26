Extension { #name : #UnixPlatform }

{ #category : #'*Zodiac-OpenSSL' }
UnixPlatform >> certificationValidationStrategy [

	^ ZdcUnixCertificateValidation
]
