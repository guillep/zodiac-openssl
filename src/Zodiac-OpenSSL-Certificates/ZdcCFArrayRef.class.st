"
I wrap a Objective C Array, I only implement the minimum logic that is needed to access the certificate store.
Remember that the Array is zero based.
"
Class {
	#name : #ZdcCFArrayRef,
	#superclass : #FFIOpaqueObject,
	#category : #'Zodiac-OpenSSL-Certificates-Stores-OSX'
}

{ #category : #'library path' }
ZdcCFArrayRef class >> ffiLibraryName [
	^ ZdcOSXSecurityLibrary
]

{ #category : #finalization }
ZdcCFArrayRef class >> finalizeResourceData: handle [
	handle isNull ifTrue: [ ^ self ].
	ZdcOSXSecurityLibrary uniqueInstance releaseHandle: handle.  
	handle beNull
]

{ #category : #accessing }
ZdcCFArrayRef >> at: index [

	^ self ffiCall: #(void* CFArrayGetValueAtIndex(self, long index))
]

{ #category : #'library path' }
ZdcCFArrayRef >> ffiLibraryName [
	^ self class ffiLibraryName
]

{ #category : #accessing }
ZdcCFArrayRef >> size [
	
	^ self ffiCall: #(long CFArrayGetCount(self))
]
