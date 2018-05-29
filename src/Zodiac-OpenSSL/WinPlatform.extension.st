Extension { #name : #WinPlatform }

{ #category : #'*Zodiac-OpenSSL' }
WinPlatform >> openSSLCertificateValidationStrategy [
	
	^ ZdcWinCertificateValidation 
]
