Extension { #name : #UnixPlatform }

{ #category : #'*Zodiac-OpenSSL' }
UnixPlatform >> openSSLCertificateValidationStrategy [

	^ ZdcUnixCertificateValidation
]
