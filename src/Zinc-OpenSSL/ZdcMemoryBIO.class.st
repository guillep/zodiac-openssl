Class {
	#name : #ZdcMemoryBIO,
	#superclass : #ZdcBIO,
	#category : #'Zinc-OpenSSL-Core'
}

{ #category : #'initializing/finalizing' }
ZdcMemoryBIO class >> bioAllocationMethod [
	
	^ self ffiCall: #(void* BIO_s_mem())
]
