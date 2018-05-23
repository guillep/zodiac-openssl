Class {
	#name : #ZnMemoryBIO,
	#superclass : #ZnBIO,
	#category : #'Zinc-OpenSSL'
}

{ #category : #'initializing/finalizing' }
ZnMemoryBIO class >> bioAllocationMethod [
	
	^ self ffiCall: #(void* BIO_s_mem())
]
