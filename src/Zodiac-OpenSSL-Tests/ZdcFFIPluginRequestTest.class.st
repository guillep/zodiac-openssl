Class {
	#name : #ZdcFFIPluginRequestTest,
	#superclass : #TestCase,
	#category : #'Zodiac-OpenSSL-Tests'
}

{ #category : #tests }
ZdcFFIPluginRequestTest >> testGoogle [
	
	ZnEasy get: 'https://www.google.com'.

]

{ #category : #tests }
ZdcFFIPluginRequestTest >> testPharo [
	
	ZnEasy get: 'https://www.pharo.org'.

]
