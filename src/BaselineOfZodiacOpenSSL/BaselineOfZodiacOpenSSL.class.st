Class {
	#name : #BaselineOfZodiacOpenSSL,
	#superclass : #BaselineOf,
	#category : #BaselineOfZodiacOpenSSL
}

{ #category : #baselines }
BaselineOfZodiacOpenSSL class >> corePackages [
	| groups |

	groups := self packagesOfGroupNamed: 'core-traits'.
	^ groups flatCollect: [ :e | self packagesOfGroupNamed: e ].
]

{ #category : #baselines }
BaselineOfZodiacOpenSSL >> baseline: spec [
	<baseline>

	spec for: #common do: [

		spec postLoadDoIt: #postload:.
	
		spec 
			package: 'Zodiac-OpenSSL';
			package: 'Zodiac-OpenSSL-Tests'.
								
		spec group: 'default' with: #('Zodiac-OpenSSL' 'Zodiac-OpenSSL-Tests').
	 ].		

]

{ #category : #baselines }
BaselineOfZodiacOpenSSL >> postload: loader [
	(Smalltalk at: #ZdcOpenSSLSession) install.
]
