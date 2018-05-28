Class {
	#name : #ZdcUnixCertificateValidation,
	#superclass : #ZdcFullCertificateValidation,
	#category : #'Zodiac-OpenSSL-CertificateValidations'
}

{ #category : #validation }
ZdcUnixCertificateValidation >> configureSSLSession: sslSession [

	| location |
	
	location := self foundLocation.
	sslSession setRootCertificateLocation: location.

	super configureSSLSession: sslSession.
]

{ #category : #locations }
ZdcUnixCertificateValidation >> foundLocation [
	^ self possibleLocations
		detect: [ :aLocation | aLocation asFileReference exists ]
		ifNone: [ ZdcOpenSSLError signal: 'Could not find valid root certificates.' ]
]

{ #category : #locations }
ZdcUnixCertificateValidation >> possibleLocations [
	^ 	#(
	'/etc/ssl/certs/ca-certificates.crt'             		"Debian/Ubuntu/Gentoo etc."
	'/etc/pki/tls/certs/ca-bundle.crt'                 	"Fedora/RHEL 6"
	'/etc/ssl/ca-bundle.pem'                           	"OpenSUSE"
	'/etc/pki/tls/cacert.pem'                          	"OpenELEC"
	'/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem'	"CentOS/RHEL 7"
	'/usr/local/etc/openssl/cert.pem'						   "OSX with Homebrew"
	'/etc/ssl/cert.pem'											"OSX"
	)
]
