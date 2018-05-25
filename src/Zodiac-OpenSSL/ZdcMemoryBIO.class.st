Class {
	#name : #ZdcMemoryBIO,
	#superclass : #ZdcBIO,
	#category : #'Zodiac-OpenSSL-Core'
}

{ #category : #'initializing/finalizing' }
ZdcMemoryBIO class >> bioAllocationMethod [
	
	^ self ffiCall: #(void* BIO_s_mem())
]
