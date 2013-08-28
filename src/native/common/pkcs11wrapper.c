/* Copyright  (c) 2002 Graz University of Technology. All rights reserved.
 *
 * Redistribution and use in  source and binary forms, with or without 
 * modification, are permitted  provided that the following conditions are met:
 *
 * 1. Redistributions of  source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in  binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  
 * 3. The end-user documentation included with the redistribution, if any, must
 *    include the following acknowledgment:
 * 
 *    "This product includes software developed by IAIK of Graz University of
 *     Technology."
 * 
 *    Alternately, this acknowledgment may appear in the software itself, if 
 *    and wherever such third-party acknowledgments normally appear.
 *  
 * 4. The names "Graz University of Technology" and "IAIK of Graz University of
 *    Technology" must not be used to endorse or promote products derived from 
 *    this software without prior written permission.
 *  
 * 5. Products derived from this software may not be called 
 *    "IAIK PKCS Wrapper", nor may "IAIK" appear in their name, without prior 
 *    written permission of Graz University of Technology.
 *  
 *  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *  OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 *  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY  OF SUCH DAMAGE.
 */

/*
 * pkcs11wrapper.c
 * 18.05.2001
 *
 * This is the implementation of the native functions of the Java to PKCS#11 interface.
 * All function use some helper functions to convert the JNI types to PKCS#11 types.
 *
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 * @author Martin Schlaeffer <schlaeff@sbox.tugraz.at>
 */

#include "pkcs11wrapper.h"


/* Include the platform specific functions; i.e. the implementations of the
 * connect and disconnect functions, which load/bind and unbind/unload the
 * native PKCS#11 module.
 */
#include "platform.c"



/* ************************************************************************** */
/* Variables global to the wrapper                                            */
/* ************************************************************************** */

/* The initArgs that enable the application to do custom mutex-handling */
#ifndef NO_CALLBACKS
jobject jInitArgsObject = NULL_PTR;
CK_C_INITIALIZE_ARGS_PTR ckpGlobalInitArgs = NULL_PTR;
#endif /* NO_CALLBACKS */


/* The list of currently connected modules. Will normally contain one element, 
 * but seldom more than a few.
 */
ModuleListNode *moduleListHead = NULL_PTR;
jobject moduleListLock = NULL_PTR;


/* The list of notify callback handles that are currently active and waiting
 * for callbacks from their sessions.
 */
#ifndef NO_CALLBACKS
NotifyListNode *notifyListHead = NULL_PTR;
jobject notifyListLock = NULL_PTR;
#endif /* NO_CALLBACKS */


#ifdef ANDROID
/* Pointer to JavaVM needed in Android */
JavaVM *g_jvm;
#endif



/* ************************************************************************** */
/* Functions called by the VM when it loads or unloads this library           */
/* ************************************************************************** */


#ifdef ANDROID
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) 
{
  g_jvm = vm;
  return JNI_VERSION_1_2 ;
}
#endif

/*
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{

}
*/

/* ************************************************************************** */
/* Helper functions                                                           */
/* ************************************************************************** */

#ifdef ANDROID
jint JNI_GetCreatedJavaVMs(JavaVM **vmBuf,
                           jsize bufLen,
                           jsize *nVMs)
{
  if (bufLen < 1) {
    *nVMs = 0;
    return 0;
  }

  *nVMs = 1;
  vmBuf[0] = g_jvm;
  return 0;
}
#endif

/*
 * This method retrieves the function pointers from the module struct. Returns NULL_PTR
 * if either the module is NULL_PTR or the function pointer list is NULL_PTR. Returns the
 * function pointer list on success.
 */
CK_FUNCTION_LIST_PTR getFunctionList(JNIEnv *env, ModuleData *moduleData)
{
  CK_FUNCTION_LIST_PTR ckpFunctions;

  ckpFunctions = moduleData->ckFunctionListPtr;
  if(ckpFunctions == NULL_PTR) { throwPKCS11RuntimeException(env, (*env)->NewStringUTF(env, "This modules does not provide methods")); return NULL_PTR; }
  return ckpFunctions;
}

/*
 * converts a given array of chars into a human readable hex string
 */
void byteArrayToHexString(char* array, int array_length, char* result, int result_length)
{
	int i = 0;
	char lut[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
	for(i; i < array_length; i++)
	{
		if(2 * i + 1 > result_length - 4) {
			result[2 * i] = '.';
			result[2 * i + 1] = '.';
			result[2 * i + 2] = '.';
			break;
		}

		result[2 * i] = lut[(array[i] & 0xF0) >> 4];
		result[2 * i + 1] = lut[array[i] & 0x0F];
	}
}

/* ************************************************************************** */
/* The native implementation of the methods of the PKCS11Implementation class */
/* ************************************************************************** */

/*
 * This method is used to do static initialization. This method is static and
 * synchronized. Summary: use this method like a static initialization block.
 *
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    initializeLibrary
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_initializeLibrary
  (JNIEnv *env, jclass thisClass)
{
  TRACE0(tag_call, __FUNCTION__, "entering");
  if (moduleListLock == NULL_PTR) {
    moduleListLock = createLockObject(env);
  }
#ifndef NO_CALLBACKS
  if (notifyListLock == NULL_PTR) {
    notifyListLock = createLockObject(env);
  }
#endif
  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/* This method is designed to do a clean-up. It releases all global resources
 * of this library. By now, this function is not called. Calling from
 * JNI_OnUnload would be an option, but some VMs do not support JNI_OnUnload.
 *
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    finalizeLibrary
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_finalizeLibrary
  (JNIEnv *env, jclass thisClass)
{
  /* remove all left lists and release the resources and the lock 
   * objects that synchroniz access to these lists.
   */
  removeAllModuleEntries(env);
  if (moduleListHead == NULL_PTR) { /* check, if we removed the last active module */
    /* remove also the moduleListLock, it is no longer used */
		if (moduleListLock != NULL_PTR) {
			destroyLockObject(env, moduleListLock);
      moduleListLock = NULL_PTR;
		}
#ifndef NO_CALLBACKS
    /* remove all left notify callback entries */
    while (removeFirstNotifyEntry(env));
    /* remove also the notifyListLock, it is no longer used */
    if (notifyListLock != NULL_PTR) {
      destroyLockObject(env, notifyListLock);
      notifyListLock = NULL_PTR;
    }
    if (jInitArgsObject != NULL_PTR) {
      (*env)->DeleteGlobalRef(env, jInitArgsObject);
    }
    if (ckpGlobalInitArgs != NULL_PTR) {
      if (ckpGlobalInitArgs->pReserved != NULL_PTR) {
        free(ckpGlobalInitArgs->pReserved);
      }
      free(ckpGlobalInitArgs);
    }
#endif /* NO_CALLBACKS */
  }
  TRACE0(tag_call, __FUNCTION__, "exiting ");
}


/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    connect
 * Signature: (Ljava/lang/String;)V
 */
/* see platform.c, because the implementation is platform dependent */


/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    disconnect
 * Signature: ()V
 */
/* see platform.c, because the implementation is platform dependent */


/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Initialize
 * Signature: (Ljava/lang/Object;Z)V
 * Parametermapping:                    *PKCS11*
 * @param   jobject jInitArgs           CK_VOID_PTR pInitArgs
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Initialize
	(JNIEnv *env, jobject obj, jobject jInitArgs, jboolean jUseUtf8)
{
  /*
   * Initalize Cryptoki
   */
  CK_C_INITIALIZE_ARGS_PTR ckpInitArgs;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");
  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

  if (jInitArgs != NULL_PTR) {
    ckpInitArgs = makeCKInitArgsAdapter(env, jInitArgs, jUseUtf8);
    if (ckpInitArgs == NULL_PTR) { return; }
  } else { 
    ckpInitArgs = NULL_PTR;
  }

	rv = (*ckpFunctions->C_Initialize)(ckpInitArgs);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  if (ckpInitArgs != NULL_PTR) {
    if (ckpInitArgs->pReserved != NULL_PTR) {
      free(ckpInitArgs->pReserved);
    }
    free(ckpInitArgs);
  }

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Finalize
 * Signature: (Ljava/lang/Object;)V
 * Parametermapping:                    *PKCS11*
 * @param   jobject jReserved           CK_VOID_PTR pReserved
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Finalize
	(JNIEnv *env, jobject obj, jobject jReserved)
{
  /*
   * Finalize Cryptoki
   */
	CK_VOID_PTR ckpReserved;
  CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckpReserved = jObjectToCKVoidPtr(jReserved);

  rv = (*ckpFunctions->C_Finalize)(ckpReserved);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetInfo
 * Signature: ()Liaik/pkcs/pkcs11/wrapper/CK_INFO;
 * Parametermapping:                    *PKCS11*
 * @return  jobject jInfoObject         CK_INFO_PTR pInfo
 */
JNIEXPORT jobject JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetInfo
	(JNIEnv *env, jobject obj)
{
	CK_INFO ckLibInfo;
	jobject jInfoObject;
  CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	rv = (*ckpFunctions->C_GetInfo)(&ckLibInfo);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	jInfoObject = ckInfoPtrToJInfo(env, &ckLibInfo);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jInfoObject ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetSlotList
 * Signature: (Z)[J
 * Parametermapping:                    *PKCS11*
 * @param   jboolean jTokenPresent      CK_BBOOL tokenPresent
 * @return  jlongArray jSlotList        CK_SLOT_ID_PTR pSlotList
 *                                      CK_ULONG_PTR pulCount
 */
JNIEXPORT jlongArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetSlotList
	(JNIEnv *env, jobject obj, jboolean jTokenPresent)
{
	CK_ULONG ckTokenNumber;
	CK_SLOT_ID_PTR ckpSlotList;
	CK_BBOOL ckTokenPresent;
	jlongArray jSlotList;
  CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckTokenPresent = jBooleanToCKBBool(jTokenPresent);

	rv = (*ckpFunctions->C_GetSlotList)(ckTokenPresent, NULL_PTR, &ckTokenNumber);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

  if (ckTokenNumber != 0) { /* only make the second call, if the number is not zero */
	  ckpSlotList = (CK_SLOT_ID_PTR) malloc(ckTokenNumber * sizeof(CK_SLOT_ID));
    if (ckpSlotList == NULL_PTR && ckTokenNumber!=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	  rv = (*ckpFunctions->C_GetSlotList)(ckTokenPresent, ckpSlotList, &ckTokenNumber);

	  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
	    jSlotList = ckULongArrayToJLongArray(env, ckpSlotList, ckTokenNumber);
	  else
	    jSlotList = NULL_PTR;

	  free(ckpSlotList);
  } else {
    jSlotList = ckULongArrayToJLongArray(env, NULL_PTR, ckTokenNumber);
  }

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSlotList ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetSlotInfo
 * Signature: (J)Liaik/pkcs/pkcs11/wrapper/CK_SLOT_INFO;
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 * @return  jobject jSlotInfoObject     CK_SLOT_INFO_PTR pInfo
 */
JNIEXPORT jobject JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetSlotInfo
	(JNIEnv *env, jobject obj, jlong jSlotID)
{
	CK_SLOT_ID ckSlotID;
	CK_SLOT_INFO ckSlotInfo;
	jobject jSlotInfoObject;
  CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSlotID = jLongToCKULong(jSlotID);

	rv = (*ckpFunctions->C_GetSlotInfo)(ckSlotID, &ckSlotInfo);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	jSlotInfoObject = ckSlotInfoPtrToJSlotInfo(env, &ckSlotInfo);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSlotInfoObject ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetTokenInfo
 * Signature: (J)Liaik/pkcs/pkcs11/wrapper/CK_TOKEN_INFO;
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 * @return  jobject jInfoTokenObject    CK_TOKEN_INFO_PTR pInfo
 */
JNIEXPORT jobject JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetTokenInfo
  (JNIEnv *env, jobject obj, jlong jSlotID)
{
	CK_SLOT_ID ckSlotID;
	CK_TOKEN_INFO ckTokenInfo;
	jobject jInfoTokenObject;
  CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSlotID = jLongToCKULong(jSlotID);

	rv = (*ckpFunctions->C_GetTokenInfo)(ckSlotID, &ckTokenInfo);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	jInfoTokenObject = ckTokenInfoPtrToJTokenInfo(env, &ckTokenInfo);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jInfoTokenObject ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetMechanismList
 * Signature: (J)[J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 * @return  jlongArray jMechanismList   CK_MECHANISM_TYPE_PTR pMechanismList
 *                                      CK_ULONG_PTR pulCount
 */
JNIEXPORT jlongArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetMechanismList
  (JNIEnv *env, jobject obj, jlong jSlotID)
{
	CK_SLOT_ID ckSlotID;
	CK_ULONG ckMechanismNumber;
	CK_MECHANISM_TYPE_PTR ckpMechanismList;
	jlongArray jMechanismList;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSlotID = jLongToCKULong(jSlotID);

	rv = (*ckpFunctions->C_GetMechanismList)(ckSlotID, NULL_PTR, &ckMechanismNumber);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpMechanismList = (CK_MECHANISM_TYPE_PTR) malloc(ckMechanismNumber * sizeof(CK_MECHANISM_TYPE));
  if (ckpMechanismList == NULL_PTR && ckMechanismNumber!=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_GetMechanismList)(ckSlotID, ckpMechanismList, &ckMechanismNumber);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jMechanismList = ckULongArrayToJLongArray(env, ckpMechanismList, ckMechanismNumber);
  else
    jMechanismList = NULL_PTR;

	free(ckpMechanismList);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jMechanismList ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetMechanismInfo
 * Signature: (JJ)Liaik/pkcs/pkcs11/wrapper/CK_MECHANISM_INFO;
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 * @param   jlong jType                 CK_MECHANISM_TYPE type
 * @return  jobject jMechanismInfo      CK_MECHANISM_INFO_PTR pInfo
 */
JNIEXPORT jobject JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetMechanismInfo
  (JNIEnv *env, jobject obj, jlong jSlotID, jlong jType)
{
	CK_SLOT_ID ckSlotID;
	CK_MECHANISM_TYPE ckMechanismType;
	CK_MECHANISM_INFO ckMechanismInfo;
	jobject jMechanismInfo;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSlotID = jLongToCKULong(jSlotID);
	ckMechanismType = jLongToCKULong(jType);

	rv = (*ckpFunctions->C_GetMechanismInfo)(ckSlotID, ckMechanismType, &ckMechanismInfo);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	jMechanismInfo = ckMechanismInfoPtrToJMechanismInfo(env, &ckMechanismInfo);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jMechanismInfo ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_InitToken
 * Signature: (J[C[CZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 * @param   jcharArray jPin             CK_UTF8CHAR_PTR pPin
 *                                      CK_ULONG ulPinLen
 * @param   jcharArray jLabel           CK_UTF8CHAR_PTR pLabel
 * @param	jboolean jUseUtf8			if new Pin shall be saved as UTF8 encoding
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1InitToken
  (JNIEnv *env, jobject obj, jlong jSlotID, jcharArray jPin, jcharArray jLabel, jboolean jUseUtf8)
{
	CK_SLOT_ID ckSlotID;
	CK_CHAR_PTR ckpPin = NULL_PTR;
	CK_UTF8CHAR_PTR ckpLabel = NULL_PTR;
	CK_ULONG ckPinLength;
	CK_ULONG ckLabelLength;
	CK_RV rv;
	CK_BBOOL ckUseUtf8;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSlotID = jLongToCKULong(jSlotID);
	ckUseUtf8 = jBooleanToCKBBool(jUseUtf8);
	if(ckUseUtf8 == TRUE){
		if(jCharArrayToCKUTF8CharArray(env, jPin, &ckpPin, &ckPinLength)) { return; }
		if(jCharArrayToCKUTF8CharArray(env, jLabel, &ckpLabel, &ckLabelLength)) { return; }
	}else{
		if(jCharArrayToCKCharArray(env, jPin, &ckpPin, &ckPinLength)) { return; }
		if(jCharArrayToCKCharArray(env, jLabel, &ckpLabel, &ckLabelLength)) { return; }
	}

	rv = (*ckpFunctions->C_InitToken)(ckSlotID, ckpPin, ckPinLength, ckpLabel);

	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
	  TRACE1(tag_info, __FUNCTION__,"InitToken return code: %ld", rv);

	free(ckpPin);
	free(ckpLabel);
  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_InitPIN
 * Signature: (J[CZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE
 * @param   jcharArray jPin             CK_CHAR_PTR pPin
 *                                      CK_ULONG ulPinLen
 * @param	jboolean jUseUtf8		if new Pin shall be saved as UTF8 encoding
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1InitPIN
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jcharArray jPin, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_CHAR_PTR ckpPin = NULL_PTR;
	CK_ULONG ckPinLength;
	CK_RV rv;
	CK_BBOOL ckUseUtf8;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckUseUtf8 = jBooleanToCKBBool(jUseUtf8);
	if(ckUseUtf8 == TRUE){
		if(jCharArrayToCKUTF8CharArray(env, jPin, &ckpPin, &ckPinLength)) { return; }
	}else{
		if(jCharArrayToCKCharArray(env, jPin, &ckpPin, &ckPinLength)) { return; }
	}

	rv = (*ckpFunctions->C_InitPIN)(ckSessionHandle, ckpPin, ckPinLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpPin);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SetPIN
 * Signature: (J[C[CZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jcharArray jOldPin          CK_CHAR_PTR pOldPin
 *                                      CK_ULONG ulOldLen
 * @param   jcharArray jNewPin          CK_CHAR_PTR pNewPin
 *                                      CK_ULONG ulNewLen
 * @param	jboolean jUseUtf8		if new Pin shall be saved as UTF8 encoding
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SetPIN
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jcharArray jOldPin, jcharArray jNewPin, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_CHAR_PTR ckpOldPin = NULL_PTR;
	CK_CHAR_PTR ckpNewPin = NULL_PTR;
	CK_ULONG ckOldPinLength;
	CK_ULONG ckNewPinLength;
	CK_RV rv;
	CK_BBOOL ckUseUtf8;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	ckUseUtf8 = jBooleanToCKBBool(jUseUtf8);
	if(ckUseUtf8 == TRUE){
		if (jCharArrayToCKUTF8CharArray(env, jOldPin, &ckpOldPin, &ckOldPinLength)) { return; }
		if (jCharArrayToCKUTF8CharArray(env, jNewPin, &ckpNewPin, &ckNewPinLength)) { return; }
	}else{
		if (jCharArrayToCKCharArray(env, jOldPin, &ckpOldPin, &ckOldPinLength)) { return; }
		if (jCharArrayToCKCharArray(env, jNewPin, &ckpNewPin, &ckNewPinLength)) { return; }
	}

	rv = (*ckpFunctions->C_SetPIN)(ckSessionHandle, ckpOldPin, ckOldPinLength, ckpNewPin, ckNewPinLength);
	ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpOldPin);
	free(ckpNewPin);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_OpenSession
 * Signature: (JJLjava/lang/Object;Liaik/pkcs/pkcs11/wrapper/CK_NOTIFY;)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 * @param   jlong jFlags                CK_FLAGS flags
 * @param   jobject jApplication        CK_VOID_PTR pApplication
 * @param   jobject jNotify             CK_NOTIFY Notify
 * @return  jlong jSessionHandle        CK_SESSION_HANDLE_PTR phSession
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1OpenSession
  (JNIEnv *env, jobject obj, jlong jSlotID, jlong jFlags, jobject jApplication, jobject jNotify)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_SLOT_ID ckSlotID;
	CK_FLAGS ckFlags;
	CK_VOID_PTR ckpApplication;
	CK_NOTIFY ckNotify;
	jlong jSessionHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;
#ifndef NO_CALLBACKS
  NotifyEncapsulation *notifyEncapsulation = NULL_PTR;
#endif /* NO_CALLBACKS */

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSlotID = jLongToCKULong(jSlotID);
	ckFlags = jLongToCKULong(jFlags);

#ifndef NO_CALLBACKS
  if (jNotify != NULL_PTR) {
    notifyEncapsulation = (NotifyEncapsulation *) malloc(sizeof(NotifyEncapsulation));
    if (notifyEncapsulation == NULL_PTR) { throwOutOfMemoryError(env); return 0L; }
    notifyEncapsulation->jApplicationData = (jApplication != NULL_PTR)
        ? (*env)->NewGlobalRef(env, jApplication)
        : NULL_PTR;
    notifyEncapsulation->jNotifyObject = (*env)->NewGlobalRef(env, jNotify);
	  ckpApplication = notifyEncapsulation;
    ckNotify = (CK_NOTIFY) &notifyCallback;
  } else {
    ckpApplication = NULL_PTR;
	  ckNotify = NULL_PTR;
  }
#else
    ckpApplication = NULL_PTR;
	  ckNotify = NULL_PTR;
#endif /* NO_CALLBACKS */

	TRACE2(tag_debug, __FUNCTION__,"  slotID=%lu, flags=%lx", ckSlotID,ckFlags);

	rv = (*ckpFunctions->C_OpenSession)(ckSlotID, ckFlags, ckpApplication, ckNotify, &ckSessionHandle);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return 0L ; }

	TRACE1(tag_info, __FUNCTION__,"got session, SessionHandle=%lu", ckSessionHandle);

	jSessionHandle = ckULongToJLong(ckSessionHandle);

#ifndef NO_CALLBACKS
  if (notifyEncapsulation != NULL_PTR) {
    /* store the notifyEncapsulation to enable later cleanup */
    putNotifyEntry(env, ckSessionHandle, notifyEncapsulation);
  }
#endif /* NO_CALLBACKS */

  TRACE0(tag_call, __FUNCTION__, "exiting ");

	return jSessionHandle ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_CloseSession
 * Signature: (J)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1CloseSession
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;
#ifndef NO_CALLBACKS
  NotifyEncapsulation *notifyEncapsulation;
  jobject jApplicationData;
#endif /* NO_CALLBACKS */
  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

  TRACE1(tag_info, __FUNCTION__, "going to close session with handle %lld", jSessionHandle);

	rv = (*ckpFunctions->C_CloseSession)(ckSessionHandle);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return; }

#ifndef NO_CALLBACKS
  notifyEncapsulation = removeNotifyEntry(env, ckSessionHandle);

  if (notifyEncapsulation != NULL_PTR) {
    /* there was a notify object used with this session, now dump the
     * encapsulation object
     */
    (*env)->DeleteGlobalRef(env, notifyEncapsulation->jNotifyObject);
    jApplicationData = notifyEncapsulation->jApplicationData;
    if (jApplicationData != NULL_PTR) {
      (*env)->DeleteGlobalRef(env, jApplicationData);
    }
    free(notifyEncapsulation);
  }
#endif /* NO_CALLBACKS */
  TRACE0(tag_call, __FUNCTION__, "exiting ");

}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_CloseAllSessions
 * Signature: (J)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSlotID               CK_SLOT_ID slotID
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1CloseAllSessions
  (JNIEnv *env, jobject obj, jlong jSlotID)
{
	CK_SLOT_ID ckSlotID;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;
#ifndef NO_CALLBACKS
  NotifyEncapsulation *notifyEncapsulation;
  jobject jApplicationData;
#endif /* NO_CALLBACKS */
  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSlotID = jLongToCKULong(jSlotID);

	rv = (*ckpFunctions->C_CloseAllSessions)(ckSlotID);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return; }

#ifndef NO_CALLBACKS
  /* Remove all notify callback helper objects. */
  while ((notifyEncapsulation = removeFirstNotifyEntry(env)) != NULL_PTR) {
    /* there was a notify object used with this session, now dump the
     * encapsulation object
     */
    (*env)->DeleteGlobalRef(env, notifyEncapsulation->jNotifyObject);
    jApplicationData = notifyEncapsulation->jApplicationData;
    if (jApplicationData != NULL_PTR) {
      (*env)->DeleteGlobalRef(env, jApplicationData);
    }
    free(notifyEncapsulation);
  }
#endif /* NO_CALLBACKS */
  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetSessionInfo
 * Signature: (J)Liaik/pkcs/pkcs11/wrapper/CK_SESSION_INFO;
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @return  jobject jSessionInfo        CK_SESSION_INFO_PTR pInfo
 */
JNIEXPORT jobject JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetSessionInfo
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_SESSION_INFO ckSessionInfo;
	jobject jSessionInfo;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;
  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	rv = (*ckpFunctions->C_GetSessionInfo)(ckSessionHandle, &ckSessionInfo);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	jSessionInfo = ckSessionInfoPtrToJSessionInfo(env, &ckSessionInfo);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSessionInfo ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetOperationState
 * Signature: (J)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @return  jbyteArray jState           CK_BYTE_PTR pOperationState
 *                                      CK_ULONG_PTR pulOperationStateLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetOperationState
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpState;
	CK_ULONG ckStateLength;
	jbyteArray jState;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	rv = (*ckpFunctions->C_GetOperationState)(ckSessionHandle, NULL_PTR, &ckStateLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpState = (CK_BYTE_PTR) malloc(ckStateLength);
  if (ckpState == NULL_PTR && ckStateLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_GetOperationState)(ckSessionHandle, ckpState, &ckStateLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jState = ckByteArrayToJByteArray(env, ckpState, ckStateLength);
  else
    jState = NULL_PTR;

	free(ckpState);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jState ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SetOperationState
 * Signature: (J[BJJ)V
 * Parametermapping:                        *PKCS11*
 * @param   jlong jSessionHandle            CK_SESSION_HANDLE hSession
 * @param   jbyteArray jOperationState      CK_BYTE_PTR pOperationState
 *                                          CK_ULONG ulOperationStateLen
 * @param   jlong jEncryptionKeyHandle      CK_OBJECT_HANDLE hEncryptionKey
 * @param   jlong jAuthenticationKeyHandle  CK_OBJECT_HANDLE hAuthenticationKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SetOperationState
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jOperationState, jlong jEncryptionKeyHandle, jlong jAuthenticationKeyHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpState = NULL_PTR;
	CK_ULONG ckStateLength;
	CK_OBJECT_HANDLE ckEncryptionKeyHandle;
	CK_OBJECT_HANDLE ckAuthenticationKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");
  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jOperationState, &ckpState, &ckStateLength)) { return; }
	ckEncryptionKeyHandle = jLongToCKULong(jEncryptionKeyHandle);
	ckAuthenticationKeyHandle = jLongToCKULong(jAuthenticationKeyHandle);

	rv = (*ckpFunctions->C_SetOperationState)(ckSessionHandle, ckpState, ckStateLength, ckEncryptionKeyHandle, ckAuthenticationKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpState);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Login
 * Signature: (JJ[CZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jUserType             CK_USER_TYPE userType
 * @param   jcharArray jPin             CK_CHAR_PTR pPin
 *                                      CK_ULONG ulPinLen
 * @param	jboolean jUseUtf8		if new Pin shall be saved as UTF8 encoding
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Login
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jUserType, jcharArray jPin, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_USER_TYPE ckUserType;
	CK_CHAR_PTR ckpPinArray = NULL_PTR;
	CK_ULONG ckPinLength;
	CK_RV rv;
	CK_BBOOL ckUseUtf8;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckUserType = jLongToCKULong(jUserType);


	ckUseUtf8 = jBooleanToCKBBool(jUseUtf8);
	if(ckUseUtf8 == TRUE){
		if (jCharArrayToCKUTF8CharArray(env, jPin, &ckpPinArray, &ckPinLength)) { return; }
	}else{
		if (jCharArrayToCKCharArray(env, jPin, &ckpPinArray, &ckPinLength)) { return; }
	}

	rv = (*ckpFunctions->C_Login)(ckSessionHandle, ckUserType, ckpPinArray, ckPinLength);

	ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpPinArray);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Logout
 * Signature: (J)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Logout
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	rv = (*ckpFunctions->C_Logout)(ckSessionHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_CreateObject
 * Signature: (J[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 * @return  jlong jObjectHandle         CK_OBJECT_HANDLE_PTR phObject
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1CreateObject
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_OBJECT_HANDLE ckObjectHandle;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	jlong jObjectHandle;
	CK_ULONG i, j, length;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return 0L; }

	rv = (*ckpFunctions->C_CreateObject)(ckSessionHandle, ckpAttributes, ckAttributesLength, &ckObjectHandle);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jObjectHandle = ckULongToJLong(ckObjectHandle);
  else
    jObjectHandle = 0L;

	for(i=0; i<ckAttributesLength; i++)
		if(ckpAttributes[i].pValue != NULL_PTR){
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
				length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
				for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpAttributes[i].pValue);
		}
	free(ckpAttributes);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jObjectHandle ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_CopyObject
 * Signature: (JJ[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jObjectHandle         CK_OBJECT_HANDLE hObject
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 * @return  jlong jNewObjectHandle      CK_OBJECT_HANDLE_PTR phNewObject
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1CopyObject
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_OBJECT_HANDLE ckObjectHandle;
	CK_OBJECT_HANDLE ckNewObjectHandle;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	jlong jNewObjectHandle;
	CK_ULONG i, j, length;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckObjectHandle = jLongToCKULong(jObjectHandle);
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return 0L; }

	rv = (*ckpFunctions->C_CopyObject)(ckSessionHandle, ckObjectHandle, ckpAttributes, ckAttributesLength, &ckNewObjectHandle);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jNewObjectHandle = ckULongToJLong(ckNewObjectHandle);
  else
    jNewObjectHandle = 0L;

	for(i=0; i<ckAttributesLength; i++)
		if(ckpAttributes[i].pValue != NULL_PTR){
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
				length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
				for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpAttributes[i].pValue);
		}
	free(ckpAttributes);

  TRACE0(tag_call, __FUNCTION__, "exiting ");

	return jNewObjectHandle ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DestroyObject
 * Signature: (JJ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jObjectHandle         CK_OBJECT_HANDLE hObject
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DestroyObject
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jObjectHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_OBJECT_HANDLE ckObjectHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckObjectHandle = jLongToCKULong(jObjectHandle);

	rv = (*ckpFunctions->C_DestroyObject)(ckSessionHandle, ckObjectHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetObjectSize
 * Signature: (JJ)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jObjectHandle         CK_OBJECT_HANDLE hObject
 * @return  jlong jObjectSize           CK_ULONG_PTR pulSize
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetObjectSize
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jObjectHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_OBJECT_HANDLE ckObjectHandle;
	CK_ULONG ckObjectSize;
	jlong jObjectSize;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckObjectHandle = jLongToCKULong(jObjectHandle);

	rv = (*ckpFunctions->C_GetObjectSize)(ckSessionHandle, ckObjectHandle, &ckObjectSize);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return 0L ; }

	jObjectSize = ckULongToJLong(ckObjectSize);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jObjectSize ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetAttributeValue
 * Signature: (JJ[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jObjectHandle         CK_OBJECT_HANDLE hObject
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetAttributeValue
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_OBJECT_HANDLE ckObjectHandle;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	CK_ULONG ckBufferLength;
	CK_ULONG length;
	CK_ULONG i, j, y;
	jobject jAttribute;
	CK_RV rv;
	CK_ULONG error = 0;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;
  signed long signedLength;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

  TRACE3(tag_debug, __FUNCTION__, "hSession=%llu, hObject=%llu, pTemplate=%p", jSessionHandle, jObjectHandle, jTemplate);

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckObjectHandle = jLongToCKULong(jObjectHandle);
	TRACE1(tag_debug, __FUNCTION__,"jAttributeArrayToCKAttributeArray now with jTemplate = %p", jTemplate);
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return; }
	TRACE2(tag_debug, __FUNCTION__,"jAttributeArrayToCKAttributeArray finished with ckpAttribute = %p, Length = %ld\n", ckpAttributes, ckAttributesLength);

	/* first set all pValue to NULL_PTR, to get the needed buffer length */
	for(i = 0; i < ckAttributesLength; i++) {
		if(ckpAttributes[i].pValue != NULL_PTR) {
			free(ckpAttributes[i].pValue);
		}
	}
	for (i = 0; i < ckAttributesLength; i++) {
		ckpAttributes[i].pValue = NULL_PTR;
	}
	TRACE0(tag_debug, __FUNCTION__, "- going to get buffer sizes");
	rv = (*ckpFunctions->C_GetAttributeValue)(ckSessionHandle, ckObjectHandle, ckpAttributes, ckAttributesLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) {
		for (i = 0; i < ckAttributesLength; i++) {
		  if(ckpAttributes[i].pValue != NULL_PTR) {
			free(ckpAttributes[i].pValue);
		  }
		}
		free(ckpAttributes);
		TRACE0(tag_call, __FUNCTION__, "exiting ");
		return ;
	}

	for (i = 0; i < ckAttributesLength; i++) {
		if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
			// allocate array
			signedLength = ckpAttributes[i].ulValueLen;
			if (signedLength != -1){
				ckBufferLength = sizeof(CK_BYTE) * ckpAttributes[i].ulValueLen;
				ckpAttributes[i].pValue = (CK_ATTRIBUTE_PTR) malloc(ckBufferLength);
				ckpAttributes[i].ulValueLen = ckBufferLength;
			}

			// clean up if array could not be allocated
			if ((ckpAttributes[i].pValue == NULL_PTR && ckBufferLength!=0) || signedLength == -1) {
				/* free previously allocated memory*/
    			for (j = 0; j < i; j++) {
					if(ckpAttributes[j].pValue != NULL_PTR) {
					  free(ckpAttributes[j].pValue);
					}
				}
				free(ckpAttributes);
				if (signedLength == -1){
					rv = 0x12;
					ckAssertReturnValueOK(env, rv, __FUNCTION__);
				  TRACE0(tag_call, __FUNCTION__, "exiting ");
					return ;
				}
				throwOutOfMemoryError(env); 
			  TRACE0(tag_call, __FUNCTION__, "exiting ");
				return ;
			}

			// initialize array to hold NULL_PTRs
			ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
			length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
			for (j=0; j<length; j++){
				ckAttributeArray[j].pValue = NULL_PTR;
			}
		}
	}

	// get ulValueLen of the attributes of a CKF_ARRAY_ATTRIBUTE if present
	TRACE0(tag_debug, __FUNCTION__, "- going to get buffer sizes of nested CKF_ARRAY_ATTRIBUTE if present");
	rv = (*ckpFunctions->C_GetAttributeValue)(ckSessionHandle, ckObjectHandle, ckpAttributes, ckAttributesLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) {
		for (i = 0; i < ckAttributesLength; i++) {
			if(ckpAttributes[i].pValue != NULL_PTR) {
				free(ckpAttributes[i].pValue);
			}
		}
		free(ckpAttributes);
	  TRACE0(tag_call, __FUNCTION__, "exiting ");
		return ;
	}

	/* now, the ulValueLength field of each attribute should hold the exact buffer length needed
	 * to allocate the needed buffers accordingly
     */
	for (i = 0; i < ckAttributesLength; i++) {
		if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
			TRACE0(tag_debug, __FUNCTION__, "- found attribute array. going to initialize the buffers of the array.");
			ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
			length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
			TRACE1(tag_debug, __FUNCTION__,"allocate mem for attributes in attribute array, length of attribute array = %ld\n", ckpAttributes[i].ulValueLen);
			if(length == 0){
				free(ckpAttributes[i].pValue);
				ckpAttributes[i].pValue = NULL;
				continue;
			}
			for (j=0; j<length; j++){
				if (ckAttributeArray[j].pValue == NULL_PTR){
					TRACE0(tag_debug, __FUNCTION__, "  Module does support ARRAY_ATTRIBUTES.");
					signedLength = ckpAttributes[i].ulValueLen;
					if (signedLength != -1){
						ckBufferLength = sizeof(CK_BYTE) * ckAttributeArray[j].ulValueLen;
						ckAttributeArray[j].pValue = (void *) malloc(ckBufferLength);
						ckAttributeArray[j].ulValueLen = ckBufferLength;
					}
					if ((ckAttributeArray[j].pValue == NULL_PTR && ckBufferLength!=0) || signedLength == -1) {
						for (y = 0; y < j; y++) {
							free(ckAttributeArray[y].pValue);
						}
						free(ckpAttributes[i].pValue);
						if (signedLength == -1)
							error = 2;
						else
							error = 1;
						break;
					}
				// if module doesn't support ARRAY ATTRIBUTES, the pointer was saved as byte array
				// and is therefore no valid pointer to a value.
				// Attribute value is set to NULL in that case.
				}else{
					TRACE0(tag_debug, __FUNCTION__, "  Module does not support ARRAY_ATTRIBUTES. Thus, the attribute value is set to NULL.");
					free(ckpAttributes[i].pValue);
					ckpAttributes[i].pValue = NULL;
					break;
				}
			}
		} else{
			signedLength = ckpAttributes[i].ulValueLen;
			if (signedLength != -1){
				ckBufferLength = sizeof(CK_BYTE) * ckpAttributes[i].ulValueLen;
				ckpAttributes[i].pValue = (void *) malloc(ckBufferLength);
				ckpAttributes[i].ulValueLen = ckBufferLength;
			}
			if (signedLength == -1)
				error = 2;
			else if (ckpAttributes[i].pValue == NULL_PTR && ckBufferLength!=0)
				error = 1;
		}
		if (error == 1 || error == 2) { 
			/* free previously allocated memory*/
			for (j = 0; j < i; j++) {
				if ((ckpAttributes[j].type == 0x40000211) || (ckpAttributes[j].type == 0x40000212)){
					ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[j].pValue;
					length = ckpAttributes[j].ulValueLen/sizeof(CK_ATTRIBUTE);
					for (y=0; y<length; y++){
						free(ckAttributeArray[y].pValue);
					} 
				}
				free(ckpAttributes[j].pValue);
			}
			free(ckpAttributes);
			if (error == 2){
				rv = 0x12;
				ckAssertReturnValueOK(env, rv, __FUNCTION__);
			  TRACE0(tag_call, __FUNCTION__, "exiting ");
				return ;
			}
			throwOutOfMemoryError(env); 
		  TRACE0(tag_call, __FUNCTION__, "exiting ");
			return ;
		}
	}

	/* now get the attributes with all values */
	TRACE0(tag_debug, __FUNCTION__, "- going to get all values");
	rv = (*ckpFunctions->C_GetAttributeValue)(ckSessionHandle, ckObjectHandle, ckpAttributes, ckAttributesLength);
    TRACE0(tag_info, __FUNCTION__,"done");
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
  {
    /* copy back the values to the Java attributes */
    for (i = 0; i < ckAttributesLength; i++) {
      jAttribute = ckAttributePtrToJAttribute(env, &(ckpAttributes[i]), obj, jSessionHandle, jObjectHandle, jUseUtf8);
      (*env)->SetObjectArrayElement(env, jTemplate, i, jAttribute);
    }
  }
  else
    TRACE0(tag_info, __FUNCTION__,"rv != OK\n");

	for (i = 0; i < ckAttributesLength; i++) {
		if (ckpAttributes[i].pValue != NULL_PTR) {
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
				length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
	 			for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpAttributes[i].pValue);
		}
	}
	free(ckpAttributes);
  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SetAttributeValue
 * Signature: (JJ[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jObjectHandle         CK_OBJECT_HANDLE hObject
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SetAttributeValue
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_OBJECT_HANDLE ckObjectHandle;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	CK_ULONG i, j, length;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckObjectHandle = jLongToCKULong(jObjectHandle);
	jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8);

	rv = (*ckpFunctions->C_SetAttributeValue)(ckSessionHandle, ckObjectHandle, ckpAttributes, ckAttributesLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	for(i=0; i<ckAttributesLength; i++) {
		if(ckpAttributes[i].pValue != NULL_PTR) {
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
			ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
			length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
			for (j=0; j<length; j++){
				free(ckAttributeArray[j].pValue);
			} 
		}
			free(ckpAttributes[i].pValue);
		}
	}
	free(ckpAttributes);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_FindObjectsInit
 * Signature: (J[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1FindObjectsInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	CK_ULONG i, j, length;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	TRACE2(tag_debug, __FUNCTION__,", hSession=%llu, pTemplate=%p", jSessionHandle, jTemplate);

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return; }

	rv = (*ckpFunctions->C_FindObjectsInit)(ckSessionHandle, ckpAttributes, ckAttributesLength);
	ckAssertReturnValueOK(env, rv, __FUNCTION__);

	for(i=0; i<ckAttributesLength; i++) {
		if(ckpAttributes[i].pValue != NULL_PTR) {
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
				length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
				for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpAttributes[i].pValue);
		}
	}
	free(ckpAttributes);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_FindObjects
 * Signature: (JJ)[J
 * Parametermapping:                        *PKCS11*
 * @param   jlong jSessionHandle            CK_SESSION_HANDLE hSession
 * @param   jlong jMaxObjectCount           CK_ULONG ulMaxObjectCount
 * @return  jlongArray jObjectHandleArray   CK_OBJECT_HANDLE_PTR phObject
 *                                          CK_ULONG_PTR pulObjectCount
 */
JNIEXPORT jlongArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1FindObjects
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jMaxObjectCount)
{
	CK_RV rv;
	CK_SESSION_HANDLE ckSessionHandle;
	CK_ULONG ckMaxObjectLength;
	CK_OBJECT_HANDLE_PTR ckpObjectHandleArray;
	CK_ULONG ckActualObjectCount;
	jlongArray jObjectHandleArray;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMaxObjectLength = jLongToCKULong(jMaxObjectCount);
	ckpObjectHandleArray = (CK_OBJECT_HANDLE_PTR) malloc(sizeof(CK_OBJECT_HANDLE) * ckMaxObjectLength);
  if (ckpObjectHandleArray == NULL_PTR && ckMaxObjectLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_FindObjects)(ckSessionHandle, ckpObjectHandleArray, ckMaxObjectLength, &ckActualObjectCount);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK) {
    TRACE3(tag_debug, __FUNCTION__, "got ArrayHandle %p limited to %lu entries having %lu entries", ckpObjectHandleArray, ckMaxObjectLength, ckActualObjectCount);
    jObjectHandleArray = ckULongArrayToJLongArray(env, ckpObjectHandleArray, ckActualObjectCount);
  }
  else
    jObjectHandleArray = NULL_PTR;

  free(ckpObjectHandleArray);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jObjectHandleArray ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_FindObjectsFinal
 * Signature: (J)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1FindObjectsFinal
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	rv = (*ckpFunctions->C_FindObjectsFinal)(ckSessionHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_EncryptInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @param   jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1EncryptInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckKeyHandle = jLongToCKULong(jKeyHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);

	rv = (*ckpFunctions->C_EncryptInit)(ckSessionHandle, &ckMechanism, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Encrypt
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG ulDataLen
 * @return  jbyteArray jEncryptedData   CK_BYTE_PTR pEncryptedData
 *                                      CK_ULONG_PTR pulEncryptedDataLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Encrypt
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jData)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData = NULL_PTR, ckpEncryptedData;
	CK_ULONG ckDataLength, ckEncryptedDataLength = 0;
	jbyteArray jEncryptedData;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	/* convert jTypes to ckTypes */
	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jData, &ckpData, &ckDataLength)) { return NULL_PTR; }
 
	/* call C_Encrypt to determine DataLength */
	rv = (*ckpFunctions->C_Encrypt)(ckSessionHandle, ckpData, ckDataLength, NULL_PTR, &ckEncryptedDataLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	/* allocate memory for Data */
	ckpEncryptedData = (CK_BYTE_PTR) malloc(ckEncryptedDataLength * sizeof(CK_BYTE));
  if (ckpEncryptedData == NULL_PTR && ckEncryptedDataLength!=0) { free(ckpEncryptedData); throwOutOfMemoryError(env); return NULL_PTR; }

	/* call C_Encrypt */
	rv = (*ckpFunctions->C_Encrypt)(ckSessionHandle, ckpData, ckDataLength, ckpEncryptedData, &ckEncryptedDataLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    /* convert ckTypes to jTypes */
    jEncryptedData = ckByteArrayToJByteArray(env, ckpEncryptedData, ckEncryptedDataLength);
  else
    jEncryptedData = NULL_PTR;

	free(ckpData);
	free(ckpEncryptedData);

  TRACE0(tag_call, __FUNCTION__, "exiting ");

	return jEncryptedData ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_EncryptUpdate
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG ulPartLen
 * @return  jbyteArray jEncryptedPart   CK_BYTE_PTR pEncryptedPart
 *                                      CK_ULONG_PTR pulEncryptedPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1EncryptUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart = NULL_PTR, ckpEncryptedPart;
	CK_ULONG ckPartLength, ckEncryptedPartLength = 0;
	jbyteArray jEncryptedPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jPart, &ckpPart, &ckPartLength)) { return NULL_PTR; }

	rv = (*ckpFunctions->C_EncryptUpdate)(ckSessionHandle, ckpPart, ckPartLength, NULL_PTR, &ckEncryptedPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpEncryptedPart = (CK_BYTE_PTR) malloc(ckEncryptedPartLength * sizeof(CK_BYTE));
  if (ckpEncryptedPart == NULL_PTR && ckEncryptedPartLength!=0) { free(ckpEncryptedPart); throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_EncryptUpdate)(ckSessionHandle, ckpPart, ckPartLength, ckpEncryptedPart, &ckEncryptedPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jEncryptedPart = ckByteArrayToJByteArray(env, ckpEncryptedPart, ckEncryptedPartLength);
  else
    jEncryptedPart = NULL_PTR;

	free(ckpPart);
	free(ckpEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jEncryptedPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_EncryptFinal
 * Signature: (J)[B
 * Parametermapping:                        *PKCS11*
 * @param   jlong jSessionHandle            CK_SESSION_HANDLE hSession
 * @return  jbyteArray jLastEncryptedPart   CK_BYTE_PTR pLastEncryptedDataPart
 *                                          CK_ULONG_PTR pulLastEncryptedDataPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1EncryptFinal
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpLastEncryptedPart;
	CK_ULONG ckLastEncryptedPartLength = 0;
	jbyteArray jLastEncryptedPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	rv = (*ckpFunctions->C_EncryptFinal)(ckSessionHandle, NULL_PTR, &ckLastEncryptedPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpLastEncryptedPart = (CK_BYTE_PTR) malloc(ckLastEncryptedPartLength * sizeof(CK_BYTE));
  if (ckpLastEncryptedPart == NULL_PTR && ckLastEncryptedPartLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_EncryptFinal)(ckSessionHandle, ckpLastEncryptedPart, &ckLastEncryptedPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jLastEncryptedPart = ckByteArrayToJByteArray(env, ckpLastEncryptedPart, ckLastEncryptedPartLength);
  else
    jLastEncryptedPart = NULL_PTR;

	free(ckpLastEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");

	return jLastEncryptedPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DecryptInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @param   jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DecryptInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckKeyHandle = jLongToCKULong(jKeyHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);

	rv = (*ckpFunctions->C_DecryptInit)(ckSessionHandle, &ckMechanism, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Decrypt
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jEncryptedData   CK_BYTE_PTR pEncryptedData
 *                                      CK_ULONG ulEncryptedDataLen
 * @return  jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG_PTR pulDataLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Decrypt
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jEncryptedData)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData, ckpEncryptedData = NULL_PTR;
	CK_ULONG ckDataLength = 0, ckEncryptedDataLength;
	jbyteArray jData;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	/* convert jTypes to ckTypes */
	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jEncryptedData, &ckpEncryptedData, &ckEncryptedDataLength)) { return NULL_PTR; }

	/* call C_Decrypt to determine DataLength */
	rv = (*ckpFunctions->C_Decrypt)(ckSessionHandle, ckpEncryptedData, ckEncryptedDataLength, NULL_PTR, &ckDataLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR; }

	/* allocate memory for Data */
	ckpData = (CK_BYTE_PTR) malloc(ckDataLength * sizeof(CK_BYTE));
  if (ckpData == NULL_PTR && ckDataLength!=0) { free(ckpEncryptedData); throwOutOfMemoryError(env); return NULL_PTR; }

	/* call C_Decrypt */
	rv = (*ckpFunctions->C_Decrypt)(ckSessionHandle, ckpEncryptedData, ckEncryptedDataLength, ckpData, &ckDataLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    /* convert ckTypes to jTypes */
    jData = ckByteArrayToJByteArray(env, ckpData, ckDataLength);
  else
    jData = NULL_PTR;

	free(ckpData);
	free(ckpEncryptedData);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jData ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DecryptUpdate
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jEncryptedPart   CK_BYTE_PTR pEncryptedPart
 *                                      CK_ULONG ulEncryptedPartLen
 * @return  jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG_PTR pulPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DecryptUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jEncryptedPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart, ckpEncryptedPart = NULL_PTR;
	CK_ULONG ckPartLength = 0, ckEncryptedPartLength;
	jbyteArray jPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jEncryptedPart, &ckpEncryptedPart, &ckEncryptedPartLength)) { return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptUpdate)(ckSessionHandle, ckpEncryptedPart, ckEncryptedPartLength, NULL_PTR, &ckPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpPart = (CK_BYTE_PTR) malloc(ckPartLength * sizeof(CK_BYTE));
  if (ckpPart == NULL_PTR && ckPartLength!=0) { free(ckpEncryptedPart); throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptUpdate)(ckSessionHandle, ckpEncryptedPart, ckEncryptedPartLength, ckpPart, &ckPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jPart = ckByteArrayToJByteArray(env, ckpPart, ckPartLength);
  else
    jPart = NULL_PTR;

	free(ckpPart);
	free(ckpEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jPart ; 
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DecryptFinal
 * Signature: (J)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @return  jbyteArray jLastPart        CK_BYTE_PTR pLastPart
 *                                      CK_ULONG_PTR pulLastPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DecryptFinal
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpLastPart;
	CK_ULONG ckLastPartLength = 0;
	jbyteArray jLastPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	rv = (*ckpFunctions->C_DecryptFinal)(ckSessionHandle, NULL_PTR, &ckLastPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpLastPart = (CK_BYTE_PTR) malloc(ckLastPartLength * sizeof(CK_BYTE));
  if (ckpLastPart == NULL_PTR && ckLastPartLength !=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptFinal)(ckSessionHandle, ckpLastPart, &ckLastPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jLastPart = ckByteArrayToJByteArray(env, ckpLastPart, ckLastPartLength);
  else
    jLastPart = NULL_PTR;

	free(ckpLastPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jLastPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DigestInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;Z)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DigestInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_SSL3_KEY_MAT_PARAMS_PTR ckpParam;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckpParam = ckMechanism.pParameter;

	rv = (*ckpFunctions->C_DigestInit)(ckSessionHandle, &ckMechanism);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Digest
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG ulDataLen
 * @return  jbyteArray jDigest          CK_BYTE_PTR pDigest
 *                                      CK_ULONG_PTR pulDigestLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Digest
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jData)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData = NULL_PTR, ckpDigest;
	CK_ULONG ckDataLength, ckDigestLength = 0;
	jbyteArray jDigest;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	/* convert jTypes to ckTypes */
	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jData, &ckpData, &ckDataLength)) { return NULL_PTR; }

	/* call C_Encrypt to determine DataLength */
	rv = (*ckpFunctions->C_Digest)(ckSessionHandle, ckpData, ckDataLength, NULL_PTR, &ckDigestLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	/* allocate memory for Data */
	ckpDigest = (CK_BYTE_PTR) malloc(ckDigestLength * sizeof(CK_BYTE));
  if (ckpDigest == NULL_PTR && ckDigestLength!=0) { free(ckpDigest); throwOutOfMemoryError(env); return NULL_PTR; }

	/* call C_Encrypt */
	rv = (*ckpFunctions->C_Digest)(ckSessionHandle, ckpData, ckDataLength, ckpDigest, &ckDigestLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    /* convert ckTypes to jTypes */
    jDigest = ckByteArrayToJByteArray(env, ckpDigest, ckDigestLength);
  else
    jDigest = NULL_PTR;

	free(ckpData);
	free(ckpDigest);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jDigest ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DigestUpdate
 * Signature: (J[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG ulDataLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DigestUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart = NULL_PTR;
	CK_ULONG ckPartLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

  jByteArrayToCKByteArray(env, jPart, &ckpPart, &ckPartLength);

	rv = (*ckpFunctions->C_DigestUpdate)(ckSessionHandle, ckpPart, ckPartLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DigestKey
 * Signature: (JJ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DigestKey
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jlong jKeyHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_ULONG ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckKeyHandle = jLongToCKULong(jKeyHandle);

	rv = (*ckpFunctions->C_DigestKey)(ckSessionHandle, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DigestFinal
 * Signature: (J)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @return  jbyteArray jDigest          CK_BYTE_PTR pDigest
 *                                      CK_ULONG_PTR pulDigestLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DigestFinal
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpDigest;
	CK_ULONG ckDigestLength = 0;
	jbyteArray jDigest;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	rv = (*ckpFunctions->C_DigestFinal)(ckSessionHandle, NULL_PTR, &ckDigestLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpDigest = (CK_BYTE_PTR) malloc(ckDigestLength * sizeof(CK_BYTE));
  if (ckpDigest == NULL_PTR && ckDigestLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }
  
	rv = (*ckpFunctions->C_DigestFinal)(ckSessionHandle, ckpDigest, &ckDigestLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jDigest = ckByteArrayToJByteArray(env, ckpDigest, ckDigestLength);
  else
    jDigest = NULL_PTR;

	free(ckpDigest);
  TRACE0(tag_call, __FUNCTION__, "exiting ");

	return jDigest ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SignInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SignInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckKeyHandle = jLongToCKULong(jKeyHandle);

	rv = (*ckpFunctions->C_SignInit)(ckSessionHandle, &ckMechanism, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Sign
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG ulDataLen
 * @return  jbyteArray jSignature       CK_BYTE_PTR pSignature
 *                                      CK_ULONG_PTR pulSignatureLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Sign
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jData)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData = NULL_PTR;
	CK_BYTE_PTR ckpSignature;
	CK_ULONG ckDataLength;
	CK_ULONG ckSignatureLength = 0;
	jbyteArray jSignature;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	jByteArrayToCKByteArray(env, jData, &ckpData, &ckDataLength);

/*
  /* START standard code * /

	/* first determine the length of the signature * /
	rv = (*ckpFunctions->C_Sign)(ckSessionHandle, ckpData, ckDataLength, NULL_PTR, &ckSignatureLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpSignature = (CK_BYTE_PTR) malloc(ckSignatureLength * sizeof(CK_BYTE));
  if (ckpSignature == NULL_PTR  && ckSignatureLength!=0) { free(ckpData); throwOutOfMemoryError(env); return NULL_PTR; }

  /* now get the signature * /
	rv = (*ckpFunctions->C_Sign)(ckSessionHandle, ckpData, ckDataLength, ckpSignature, &ckSignatureLength);
 /* END standard code * /
 */


  /* START workaround code for operation abort bug in pkcs#11 of Datakey and iButton */
  ckSignatureLength = 512;
	ckpSignature = (CK_BYTE_PTR) malloc(ckSignatureLength * sizeof(CK_BYTE));
  if (ckpSignature == NULL_PTR && ckSignatureLength!=0) { free(ckpData); throwOutOfMemoryError(env); return NULL_PTR; }
	rv = (*ckpFunctions->C_Sign)(ckSessionHandle, ckpData, ckDataLength, ckpSignature, &ckSignatureLength);
  
  if (rv == CKR_BUFFER_TOO_SMALL) {
    free(ckpSignature);
	  ckpSignature = (CK_BYTE_PTR) malloc(ckSignatureLength * sizeof(CK_BYTE));
    if (ckpSignature == NULL_PTR && ckSignatureLength!=0) { free(ckpData); throwOutOfMemoryError(env); return NULL_PTR; }
	  rv = (*ckpFunctions->C_Sign)(ckSessionHandle, ckpData, ckDataLength, ckpSignature, &ckSignatureLength);
  }
  /* END workaround code */

  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jSignature = ckByteArrayToJByteArray(env, ckpSignature, ckSignatureLength);
  else
    jSignature = NULL_PTR;

	free(ckpData);
	free(ckpSignature);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSignature ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SignUpdate
 * Signature: (J[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG ulPartLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SignUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart = NULL_PTR;
	CK_ULONG ckPartLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jPart, &ckpPart, &ckPartLength)) { return; }

	rv = (*ckpFunctions->C_SignUpdate)(ckSessionHandle, ckpPart, ckPartLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SignFinal
 * Signature: (J)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @return  jbyteArray jSignature       CK_BYTE_PTR pSignature
 *                                      CK_ULONG_PTR pulSignatureLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SignFinal
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpSignature;
	CK_ULONG ckSignatureLength = 0;
	jbyteArray jSignature;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	/* first determine the length of the signature */
	rv = (*ckpFunctions->C_SignFinal)(ckSessionHandle, NULL_PTR, &ckSignatureLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpSignature = (CK_BYTE_PTR) malloc(ckSignatureLength * sizeof(CK_BYTE));
  if (ckpSignature == NULL_PTR && ckSignatureLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }

	/* now get the signature */
	rv = (*ckpFunctions->C_SignFinal)(ckSessionHandle, ckpSignature, &ckSignatureLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jSignature = ckByteArrayToJByteArray(env, ckpSignature, ckSignatureLength);
  else
    jSignature = NULL_PTR;

	free(ckpSignature);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSignature ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SignRecoverInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SignRecoverInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckKeyHandle = jLongToCKULong(jKeyHandle);

	rv = (*ckpFunctions->C_SignRecoverInit)(ckSessionHandle, &ckMechanism, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SignRecover
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG ulDataLen
 * @return  jbyteArray jSignature       CK_BYTE_PTR pSignature
 *                                      CK_ULONG_PTR pulSignatureLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SignRecover
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jData)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData = NULL_PTR;
	CK_BYTE_PTR ckpSignature;
	CK_ULONG ckDataLength;
	CK_ULONG ckSignatureLength = 0;
	jbyteArray jSignature;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jData, &ckpData, &ckDataLength)) { return NULL_PTR; }

	/* first determine the length of the signature */
	rv = (*ckpFunctions->C_SignRecover)(ckSessionHandle, ckpData, ckDataLength, NULL_PTR, &ckSignatureLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpSignature = (CK_BYTE_PTR) malloc(ckSignatureLength * sizeof(CK_BYTE));
  if (ckpSignature == NULL_PTR && ckSignatureLength!=0) { free(ckpData); throwOutOfMemoryError(env); return NULL_PTR; }

	/* now get the signature */
	rv = (*ckpFunctions->C_SignRecover)(ckSessionHandle, ckpData, ckDataLength, ckpSignature, &ckSignatureLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jSignature = ckByteArrayToJByteArray(env, ckpSignature, ckSignatureLength);
  else
    jSignature = NULL_PTR;

	free(ckpData);
	free(ckpSignature);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSignature ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_VerifyInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1VerifyInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;


  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckKeyHandle = jLongToCKULong(jKeyHandle);

	rv = (*ckpFunctions->C_VerifyInit)(ckSessionHandle, &ckMechanism, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_Verify
 * Signature: (J[B[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG ulDataLen
 * @param   jbyteArray jSignature       CK_BYTE_PTR pSignature
 *                                      CK_ULONG_PTR pulSignatureLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1Verify
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jData, jbyteArray jSignature)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData = NULL_PTR;
	CK_BYTE_PTR ckpSignature = NULL_PTR;
	CK_ULONG ckDataLength;
	CK_ULONG ckSignatureLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jData, &ckpData, &ckDataLength)) { return; }
	if (jByteArrayToCKByteArray(env, jSignature, &ckpSignature, &ckSignatureLength)) { return; }

	/* verify the signature */
	rv = (*ckpFunctions->C_Verify)(ckSessionHandle, ckpData, ckDataLength, ckpSignature, ckSignatureLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpData);
	free(ckpSignature);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_VerifyUpdate
 * Signature: (J[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG ulPartLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1VerifyUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart = NULL_PTR;
	CK_ULONG ckPartLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jPart, &ckpPart, &ckPartLength)) { return; }

	rv = (*ckpFunctions->C_VerifyUpdate)(ckSessionHandle, ckpPart, ckPartLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_VerifyFinal
 * Signature: (J[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jSignature       CK_BYTE_PTR pSignature
 *                                      CK_ULONG ulSignatureLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1VerifyFinal
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jSignature)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpSignature = NULL_PTR;
	CK_ULONG ckSignatureLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jSignature, &ckpSignature, &ckSignatureLength)) { return; }

	/* verify the signature */
	rv = (*ckpFunctions->C_VerifyFinal)(ckSessionHandle, ckpSignature, ckSignatureLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpSignature);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_VerifyRecoverInit
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JZ)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1VerifyRecoverInit
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckKeyHandle = jLongToCKULong(jKeyHandle);

	rv = (*ckpFunctions->C_VerifyRecoverInit)(ckSessionHandle, &ckMechanism, ckKeyHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_VerifyRecover
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jSignature       CK_BYTE_PTR pSignature
 *                                      CK_ULONG ulSignatureLen
 * @return  jbyteArray jData            CK_BYTE_PTR pData
 *                                      CK_ULONG_PTR pulDataLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1VerifyRecover
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jSignature)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpData;
	CK_BYTE_PTR ckpSignature = NULL_PTR;
	CK_ULONG ckDataLength = 0;
	CK_ULONG ckSignatureLength;
	jbyteArray jData;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jSignature, &ckpSignature, &ckSignatureLength)) { return NULL_PTR; }

	/* first determine the length of the signature */
	rv = (*ckpFunctions->C_VerifyRecover)(ckSessionHandle, ckpSignature, ckSignatureLength, NULL_PTR, &ckDataLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpData = (CK_BYTE_PTR) malloc(ckDataLength * sizeof(CK_BYTE));
  if (ckpData == NULL_PTR && ckDataLength!=0) { free(ckpSignature); throwOutOfMemoryError(env); return NULL_PTR; }

	/* now get the signature */
	rv = (*ckpFunctions->C_VerifyRecover)(ckSessionHandle, ckpSignature, ckSignatureLength, ckpData, &ckDataLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jData = ckByteArrayToJByteArray(env, ckpData, ckDataLength);
  else
    jData = NULL_PTR;

	free(ckpData);
	free(ckpSignature);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jData ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DigestEncryptUpdate
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG ulPartLen
 * @return  jbyteArray jEncryptedPart   CK_BYTE_PTR pEncryptedPart
 *                                      CK_ULONG_PTR pulEncryptedPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DigestEncryptUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart = NULL_PTR, ckpEncryptedPart;
	CK_ULONG ckPartLength, ckEncryptedPartLength = 0;
	jbyteArray jEncryptedPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jPart, &ckpPart, &ckPartLength)) { return NULL_PTR; }

	rv = (*ckpFunctions->C_DigestEncryptUpdate)(ckSessionHandle, ckpPart, ckPartLength, NULL_PTR, &ckEncryptedPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpEncryptedPart = (CK_BYTE_PTR) malloc(ckEncryptedPartLength * sizeof(CK_BYTE));
  if (ckpEncryptedPart == NULL_PTR && ckEncryptedPartLength!=0) { free(ckpPart); throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_DigestEncryptUpdate)(ckSessionHandle, ckpPart, ckPartLength, ckpEncryptedPart, &ckEncryptedPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jEncryptedPart = ckByteArrayToJByteArray(env, ckpEncryptedPart, ckEncryptedPartLength);
  else
    jEncryptedPart = NULL_PTR;

	free(ckpPart);
	free(ckpEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jEncryptedPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DecryptDigestUpdate
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jEncryptedPart   CK_BYTE_PTR pEncryptedPart
 *                                      CK_ULONG ulEncryptedPartLen
 * @return  jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG_PTR pulPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DecryptDigestUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jEncryptedPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart, ckpEncryptedPart = NULL_PTR;
	CK_ULONG ckPartLength = 0, ckEncryptedPartLength;
	jbyteArray jPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jEncryptedPart, &ckpEncryptedPart, &ckEncryptedPartLength)) { return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptDigestUpdate)(ckSessionHandle, ckpEncryptedPart, ckEncryptedPartLength, NULL_PTR, &ckPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR; }

	ckpPart = (CK_BYTE_PTR) malloc(ckPartLength * sizeof(CK_BYTE));
  if (ckpPart == NULL_PTR && ckPartLength!=0) { free(ckpEncryptedPart); throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptDigestUpdate)(ckSessionHandle, ckpEncryptedPart, ckEncryptedPartLength, ckpPart, &ckPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jPart = ckByteArrayToJByteArray(env, ckpPart, ckPartLength);
  else
    jPart = NULL_PTR;

	free(ckpPart);
	free(ckpEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SignEncryptUpdate
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG ulPartLen
 * @return  jbyteArray jEncryptedPart   CK_BYTE_PTR pEncryptedPart
 *                                      CK_ULONG_PTR pulEncryptedPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SignEncryptUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart = NULL_PTR, ckpEncryptedPart;
	CK_ULONG ckPartLength, ckEncryptedPartLength = 0;
	jbyteArray jEncryptedPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jPart, &ckpPart, &ckPartLength)) { return NULL_PTR; }

	rv = (*ckpFunctions->C_SignEncryptUpdate)(ckSessionHandle, ckpPart, ckPartLength, NULL_PTR, &ckEncryptedPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpEncryptedPart = (CK_BYTE_PTR) malloc(ckEncryptedPartLength * sizeof(CK_BYTE));
  if (ckpEncryptedPart == NULL_PTR && ckEncryptedPartLength!=0) { free(ckpPart); throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_SignEncryptUpdate)(ckSessionHandle, ckpPart, ckPartLength, ckpEncryptedPart, &ckEncryptedPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jEncryptedPart = ckByteArrayToJByteArray(env, ckpEncryptedPart, ckEncryptedPartLength);
  else
    jEncryptedPart = NULL_PTR;

	free(ckpPart);
	free(ckpEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jEncryptedPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DecryptVerifyUpdate
 * Signature: (J[B)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jEncryptedPart   CK_BYTE_PTR pEncryptedPart
 *                                      CK_ULONG ulEncryptedPartLen
 * @return  jbyteArray jPart            CK_BYTE_PTR pPart
 *                                      CK_ULONG_PTR pulPartLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DecryptVerifyUpdate
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jEncryptedPart)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpPart, ckpEncryptedPart = NULL_PTR;
	CK_ULONG ckPartLength = 0, ckEncryptedPartLength;
	jbyteArray jPart;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jEncryptedPart, &ckpEncryptedPart, &ckEncryptedPartLength)) { return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptVerifyUpdate)(ckSessionHandle, ckpEncryptedPart, ckEncryptedPartLength, NULL_PTR, &ckPartLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR ; }

	ckpPart = (CK_BYTE_PTR) malloc(ckPartLength * sizeof(CK_BYTE));
  if (ckpPart == NULL_PTR && ckPartLength!=0) { free(ckpEncryptedPart); throwOutOfMemoryError(env); return NULL_PTR; }

	rv = (*ckpFunctions->C_DecryptVerifyUpdate)(ckSessionHandle, ckpEncryptedPart, ckEncryptedPartLength, ckpPart, &ckPartLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jPart = ckByteArrayToJByteArray(env, ckpPart, ckPartLength);
  else
    jPart = NULL_PTR;

	free(ckpPart);
	free(ckpEncryptedPart);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jPart ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GenerateKey
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE_PTR phKey
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GenerateKey
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	CK_OBJECT_HANDLE ckKeyHandle;
	jlong jKeyHandle;
	CK_ULONG i, j, length;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
  if ((*env)->ExceptionOccurred(env)) { return 0L ; }
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return 0L; }

	rv = (*ckpFunctions->C_GenerateKey)(ckSessionHandle, &ckMechanism, ckpAttributes, ckAttributesLength, &ckKeyHandle);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jKeyHandle = ckULongToJLong(ckKeyHandle);
  else
    jKeyHandle = 0L;

	for(i=0; i<ckAttributesLength; i++) {
		if(ckpAttributes[i].pValue != NULL_PTR) {
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
				length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
				for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpAttributes[i].pValue);
		}
	}
	free(ckpAttributes);

  /* cheack, if we must give a initialization vector back to Java */
  switch (ckMechanism.mechanism) {
    case CKM_PBE_MD2_DES_CBC:
    case CKM_PBE_MD5_DES_CBC:
    case CKM_PBE_MD5_CAST_CBC:
    case CKM_PBE_MD5_CAST3_CBC:
    case CKM_PBE_MD5_CAST128_CBC:
    /* case CKM_PBE_MD5_CAST5_CBC:  the same as CKM_PBE_MD5_CAST128_CBC */
    case CKM_PBE_SHA1_CAST128_CBC:
    /* case CKM_PBE_SHA1_CAST5_CBC: the same as CKM_PBE_SHA1_CAST128_CBC */
      /* we must copy back the initialization vector to the jMechanism object */
      copyBackPBEInitializationVector(env, &ckMechanism, jMechanism);
      break;
  }

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jKeyHandle ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GenerateKeyPair
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)[J
 * Parametermapping:                          *PKCS11*
 * @param   jlong jSessionHandle              CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism                CK_MECHANISM_PTR pMechanism
 * @param   jobjectArray jPublicKeyTemplate   CK_ATTRIBUTE_PTR pPublicKeyTemplate
 *                                            CK_ULONG ulPublicKeyAttributeCount
 * @param   jobjectArray jPrivateKeyTemplate  CK_ATTRIBUTE_PTR pPrivateKeyTemplate
 *                                            CK_ULONG ulPrivateKeyAttributeCount
 * @return  jlongArray jKeyHandles            CK_OBJECT_HANDLE_PTR phPublicKey
 *                                            CK_OBJECT_HANDLE_PTR phPublicKey
 */
JNIEXPORT jlongArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GenerateKeyPair
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism,
   jobjectArray jPublicKeyTemplate, jobjectArray jPrivateKeyTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_ATTRIBUTE_PTR ckpPublicKeyAttributes = NULL_PTR;
	CK_ATTRIBUTE_PTR ckpPrivateKeyAttributes = NULL_PTR;
	CK_ATTRIBUTE_PTR ckAttributeArray;
	CK_ULONG ckPublicKeyAttributesLength;
	CK_ULONG ckPrivateKeyAttributesLength;
	CK_OBJECT_HANDLE_PTR ckpPublicKeyHandle;	/* pointer to Public Key */
	CK_OBJECT_HANDLE_PTR ckpPrivateKeyHandle;	/* pointer to Private Key */
	CK_OBJECT_HANDLE_PTR ckpKeyHandles;			/* pointer to array with Public and Private Key */
	CK_ULONG i, j, length;
	jlongArray jKeyHandles;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	if (jAttributeArrayToCKAttributeArray(env, jPublicKeyTemplate, &ckpPublicKeyAttributes, &ckPublicKeyAttributesLength, jUseUtf8)) { return NULL_PTR; }
	if (jAttributeArrayToCKAttributeArray(env, jPrivateKeyTemplate, &ckpPrivateKeyAttributes, &ckPrivateKeyAttributesLength, jUseUtf8)) { return NULL_PTR; }
	ckpKeyHandles = (CK_OBJECT_HANDLE_PTR) malloc(2 * sizeof(CK_OBJECT_HANDLE));
  if (ckpKeyHandles == NULL_PTR) { free(ckpPublicKeyAttributes); free(ckpPrivateKeyAttributes); throwOutOfMemoryError(env); return NULL_PTR; }
	ckpPublicKeyHandle = ckpKeyHandles;		/* first element of array is Public Key */
	ckpPrivateKeyHandle = (ckpKeyHandles + 1);	/* second element of array is Private Key */

	rv = (*ckpFunctions->C_GenerateKeyPair)(ckSessionHandle, &ckMechanism,
									   ckpPublicKeyAttributes, ckPublicKeyAttributesLength,
									   ckpPrivateKeyAttributes, ckPrivateKeyAttributesLength,
									   ckpPublicKeyHandle, ckpPrivateKeyHandle);

  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jKeyHandles = ckULongArrayToJLongArray(env, ckpKeyHandles, 2);
  else
    jKeyHandles = NULL_PTR;

	for(i=0; i<ckPublicKeyAttributesLength; i++) {
		if(ckpPublicKeyAttributes[i].pValue != NULL_PTR) {
			if ((ckpPublicKeyAttributes[i].type == 0x40000211) || (ckpPublicKeyAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpPublicKeyAttributes[i].pValue;
				length = ckpPublicKeyAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
	 			for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpPublicKeyAttributes[i].pValue);
		}
	}
	free(ckpPublicKeyAttributes);

	for(i=0; i<ckPrivateKeyAttributesLength; i++) {
		if(ckpPrivateKeyAttributes[i].pValue != NULL_PTR) {
			if ((ckpPrivateKeyAttributes[i].type == 0x40000211) || (ckpPrivateKeyAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpPrivateKeyAttributes[i].pValue;
				length = ckpPrivateKeyAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
	 			for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpPrivateKeyAttributes[i].pValue);
		}
	}
	free(ckpPrivateKeyAttributes);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

	free(ckpKeyHandles);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jKeyHandles ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_WrapKey
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;JJZ)[B
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @param   jlong jWrappingKeyHandle    CK_OBJECT_HANDLE hWrappingKey
 * @param   jlong jKeyHandle            CK_OBJECT_HANDLE hKey
 * @return  jbyteArray jWrappedKey      CK_BYTE_PTR pWrappedKey
 *                                      CK_ULONG_PTR pulWrappedKeyLen
 */
JNIEXPORT jbyteArray JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1WrapKey
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jWrappingKeyHandle, jlong jKeyHandle, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckWrappingKeyHandle;
	CK_OBJECT_HANDLE ckKeyHandle;
	CK_BYTE_PTR ckpWrappedKey;
	CK_ULONG ckWrappedKeyLength = 0;
	jbyteArray jWrappedKey;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return NULL_PTR; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return NULL_PTR; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckWrappingKeyHandle = jLongToCKULong(jWrappingKeyHandle);
	ckKeyHandle = jLongToCKULong(jKeyHandle);

	rv = (*ckpFunctions->C_WrapKey)(ckSessionHandle, &ckMechanism, ckWrappingKeyHandle, ckKeyHandle, NULL_PTR, &ckWrappedKeyLength);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return NULL_PTR; }

	ckpWrappedKey = (CK_BYTE_PTR) malloc(ckWrappedKeyLength * sizeof(CK_BYTE));
  if (ckpWrappedKey == NULL_PTR && ckWrappedKeyLength!=0) {
    if(ckMechanism.pParameter != NULL_PTR) {
		  free(ckMechanism.pParameter);
    }
    throwOutOfMemoryError(env); 
    return NULL_PTR;
  }

	rv = (*ckpFunctions->C_WrapKey)(ckSessionHandle, &ckMechanism, ckWrappingKeyHandle, ckKeyHandle, ckpWrappedKey, &ckWrappedKeyLength);
  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jWrappedKey = ckByteArrayToJByteArray(env, ckpWrappedKey, ckWrappedKeyLength);
  else
    jWrappedKey = NULL_PTR;

	free(ckpWrappedKey);
  if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
  }

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jWrappedKey ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_UnwrapKey
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;J[B[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @param   jlong jUnwrappingKeyHandle  CK_OBJECT_HANDLE hUnwrappingKey
 * @param   jbyteArray jWrappedKey      CK_BYTE_PTR pWrappedKey
 *                                      CK_ULONG_PTR pulWrappedKeyLen
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE_PTR phKey
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1UnwrapKey
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jUnwrappingKeyHandle,
   jbyteArray jWrappedKey, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckUnwrappingKeyHandle;
	CK_BYTE_PTR ckpWrappedKey = NULL_PTR;
	CK_ULONG ckWrappedKeyLength;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	CK_OBJECT_HANDLE ckKeyHandle;
	jlong jKeyHandle;
	CK_ULONG i, j, length;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckUnwrappingKeyHandle = jLongToCKULong(jUnwrappingKeyHandle);
	if (jByteArrayToCKByteArray(env, jWrappedKey, &ckpWrappedKey, &ckWrappedKeyLength)) { return 0L; }
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return 0L; }

	rv = (*ckpFunctions->C_UnwrapKey)(ckSessionHandle, &ckMechanism, ckUnwrappingKeyHandle,
								 ckpWrappedKey, ckWrappedKeyLength,
								 ckpAttributes, ckAttributesLength, &ckKeyHandle);

  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK)
    jKeyHandle = ckLongToJLong(ckKeyHandle);
  else
    jKeyHandle = 0L;

  for(i=0; i<ckAttributesLength; i++) {
    if(ckpAttributes[i].pValue != NULL_PTR) {
		if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
			ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
			length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
			for (j=0; j<length; j++){
				free(ckAttributeArray[j].pValue);
			} 
		}
		free(ckpAttributes[i].pValue);
    }
  }
	free(ckpAttributes);

  /* cheack, if we must give a initialization vector back to Java */
  if (ckMechanism.mechanism == CKM_KEY_WRAP_SET_OAEP) {
    /* we must copy back the unwrapped key info to the jMechanism object */
    copyBackSetUnwrappedKey(env, &ckMechanism, jMechanism);
  }

	free(ckpWrappedKey);
  if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
  }

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jKeyHandle ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_DeriveKey
 * Signature: (JLiaik/pkcs/pkcs11/wrapper/CK_MECHANISM;J[Liaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE;Z)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jobject jMechanism          CK_MECHANISM_PTR pMechanism
 * @param   jlong jBaseKeyHandle        CK_OBJECT_HANDLE hBaseKey
 * @param   jobjectArray jTemplate      CK_ATTRIBUTE_PTR pTemplate
 *                                      CK_ULONG ulCount
 * @return  jlong jKeyHandle            CK_OBJECT_HANDLE_PTR phKey
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1DeriveKey
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jobject jMechanism, jlong jBaseKeyHandle, jobjectArray jTemplate, jboolean jUseUtf8)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_MECHANISM ckMechanism;
	CK_OBJECT_HANDLE ckBaseKeyHandle;
	CK_ATTRIBUTE_PTR ckpAttributes = NULL_PTR, ckAttributeArray;
	CK_ULONG ckAttributesLength;
	CK_OBJECT_HANDLE ckKeyHandle;
	jlong jKeyHandle;
	CK_ULONG i, j, length;
	CK_RV rv;	
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	ckMechanism = jMechanismToCKMechanism(env, jMechanism, jUseUtf8);
	ckBaseKeyHandle = jLongToCKULong(jBaseKeyHandle);
	if (jAttributeArrayToCKAttributeArray(env, jTemplate, &ckpAttributes, &ckAttributesLength, jUseUtf8)) { return 0L; }

	rv = (*ckpFunctions->C_DeriveKey)(ckSessionHandle, &ckMechanism, ckBaseKeyHandle,
								 ckpAttributes, ckAttributesLength, &ckKeyHandle);

  if(ckAssertReturnValueOK(env, rv, __FUNCTION__) == CK_ASSERT_OK) {
    jKeyHandle = ckLongToJLong(ckKeyHandle);
		if (ckMechanism.mechanism == CKM_SSL3_MASTER_KEY_DERIVE) {
			/* we must copy back the client version */
			copyBackClientVersion(env, &ckMechanism, jMechanism);
		}
		if (ckMechanism.mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE) {
			/* we must copy back the unwrapped key info to the jMechanism object */
			copyBackSSLKeyMatParams(env, &ckMechanism, jMechanism);
		}
  }
  else
    jKeyHandle = 0L;

	for(i=0; i<ckAttributesLength; i++) {
		if(ckpAttributes[i].pValue != NULL_PTR) {
			if ((ckpAttributes[i].type == 0x40000211) || (ckpAttributes[i].type == 0x40000212)){
				ckAttributeArray = (CK_ATTRIBUTE_PTR)ckpAttributes[i].pValue;
				length = ckpAttributes[i].ulValueLen/sizeof(CK_ATTRIBUTE);
				for (j=0; j<length; j++){
					free(ckAttributeArray[j].pValue);
				} 
			}
			free(ckpAttributes[i].pValue);
		}
	}
	free(ckpAttributes);

	if(ckMechanism.pParameter != NULL_PTR) {
		freeCKMechanismParameter(&ckMechanism);
	}

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jKeyHandle ;
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_SeedRandom
 * Signature: (J[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jSeed            CK_BYTE_PTR pSeed
 *                                      CK_ULONG ulSeedLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1SeedRandom
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jSeed)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_BYTE_PTR ckpSeed = NULL_PTR;
	CK_ULONG ckSeedLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);
	if (jByteArrayToCKByteArray(env, jSeed, &ckpSeed, &ckSeedLength)) { return; }

	rv = (*ckpFunctions->C_SeedRandom)(ckSessionHandle, ckpSeed, ckSeedLength);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

	free(ckpSeed);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GenerateRandom
 * Signature: (J[B)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 * @param   jbyteArray jRandomData      CK_BYTE_PTR pRandomData
 *                                      CK_ULONG ulRandomDataLen
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GenerateRandom
  (JNIEnv *env, jobject obj, jlong jSessionHandle, jbyteArray jRandomData)
{
	CK_SESSION_HANDLE ckSessionHandle;
  jbyte *jRandomBuffer;
  jlong jRandomBufferLength;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	jRandomBufferLength = (*env)->GetArrayLength(env, jRandomData);
	jRandomBuffer = (*env)->GetByteArrayElements(env, jRandomData, NULL_PTR);

	rv = (*ckpFunctions->C_GenerateRandom)(ckSessionHandle, 
                                         (CK_BYTE_PTR) jRandomBuffer, 
                                         jLongToCKULong(jRandomBufferLength));
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  /* copy back generated bytes */
	(*env)->ReleaseByteArrayElements(env, jRandomData, jRandomBuffer, 0);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_GetFunctionStatus
 * Signature: (J)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1GetFunctionStatus
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	/* C_GetFunctionStatus should always return CKR_FUNCTION_NOT_PARALLEL */
	rv = (*ckpFunctions->C_GetFunctionStatus)(ckSessionHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_CancelFunction
 * Signature: (J)V
 * Parametermapping:                    *PKCS11*
 * @param   jlong jSessionHandle        CK_SESSION_HANDLE hSession
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1CancelFunction
  (JNIEnv *env, jobject obj, jlong jSessionHandle)
{
	CK_SESSION_HANDLE ckSessionHandle;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return; }

	ckSessionHandle = jLongToCKULong(jSessionHandle);

	/* C_GetFunctionStatus should always return CKR_FUNCTION_NOT_PARALLEL */
	rv = (*ckpFunctions->C_CancelFunction)(ckSessionHandle);
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    C_WaitForSlotEvent
 * Signature: (JLjava/lang/Object;)J
 * Parametermapping:                    *PKCS11*
 * @param   jlong jFlags                CK_FLAGS flags
 * @param   jobject jReserved           CK_VOID_PTR pReserved
 * @return  jlong jSlotID               CK_SLOT_ID_PTR pSlot
 */
JNIEXPORT jlong JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_C_1WaitForSlotEvent
  (JNIEnv *env, jobject obj, jlong jFlags, jobject jReserved)
{
	CK_FLAGS ckFlags;
	CK_SLOT_ID ckSlotID;
	jlong jSlotID;
	CK_RV rv;
  ModuleData *moduleData;
  CK_FUNCTION_LIST_PTR ckpFunctions;

  TRACE0(tag_call, __FUNCTION__, "entering");

  moduleData = getModuleEntry(env, obj);
  if (moduleData == NULL_PTR) { throwDisconnectedRuntimeException(env); return 0L; }
  ckpFunctions = getFunctionList(env, moduleData);
  if (ckpFunctions == NULL_PTR) { return 0L; }

	ckFlags = jLongToCKULong(jFlags);

	rv = (*ckpFunctions->C_WaitForSlotEvent)(ckFlags, &ckSlotID, NULL_PTR);
	if(ckAssertReturnValueOK(env, rv, __FUNCTION__) != CK_ASSERT_OK) { return 0L; }

	jSlotID = ckULongToJLong(ckSlotID);

  TRACE0(tag_call, __FUNCTION__, "exiting ");
	return jSlotID ;
}

/* ************************************************************************** */
/* Now come the functions for mutex handling and notification callbacks       */
/* ************************************************************************** */

/*
 * converts the InitArgs object to a CK_C_INITIALIZE_ARGS structure and sets the functions
 * that will call the right Java mutex functions
 *
 * @param env - used to call JNI funktions to get the Java classes, objects, methods and fields
 * @param pInitArgs - the InitArgs object with the Java mutex functions to call
 * @return - the pointer to the CK_C_INITIALIZE_ARGS structure with the functions that will call
 *           the corresponding Java functions
 */
CK_C_INITIALIZE_ARGS_PTR makeCKInitArgsAdapter(JNIEnv *env, jobject jInitArgs, jboolean jUseUtf8)
{
	CK_C_INITIALIZE_ARGS_PTR ckpInitArgs;
	jclass jInitArgsClass = (*env)->FindClass(env, CLASS_C_INITIALIZE_ARGS);
	jfieldID fieldID;
	jlong jFlags;
	jobject jReserved;
  CK_ULONG ckReservedLength;
#ifndef NO_CALLBACKS
	jobject jMutexHandler;
#endif /* NO_CALLBACKS */

	if(jInitArgs == NULL_PTR) {
		return NULL_PTR;
	}

	/* convert the Java InitArgs object to a pointer to a CK_C_INITIALIZE_ARGS structure */
	ckpInitArgs = (CK_C_INITIALIZE_ARGS_PTR) malloc(sizeof(CK_C_INITIALIZE_ARGS));
  if (ckpInitArgs == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }

	/* Set the mutex functions that will call the Java mutex functions, but
   * only set it, if the field is not NULL_PTR.
   */
#ifdef NO_CALLBACKS
  ckpInitArgs->CreateMutex = NULL_PTR;
  ckpInitArgs->DestroyMutex = NULL_PTR;
  ckpInitArgs->LockMutex = NULL_PTR;
  ckpInitArgs->UnlockMutex = NULL_PTR;
#else
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "CreateMutex", CLASS_NAME(CLASS_CREATEMUTEX));
	assert(fieldID != 0);
	jMutexHandler = (*env)->GetObjectField(env, jInitArgs, fieldID);
  ckpInitArgs->CreateMutex = (jMutexHandler != NULL_PTR) ? &callJCreateMutex : NULL_PTR;

	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "DestroyMutex", CLASS_NAME(CLASS_DESTROYMUTEX));
	assert(fieldID != 0);
	jMutexHandler = (*env)->GetObjectField(env, jInitArgs, fieldID);
  ckpInitArgs->DestroyMutex = (jMutexHandler != NULL_PTR) ? &callJDestroyMutex : NULL_PTR;

	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "LockMutex", CLASS_NAME(CLASS_LOCKMUTEX));
	assert(fieldID != 0);
	jMutexHandler = (*env)->GetObjectField(env, jInitArgs, fieldID);
  ckpInitArgs->LockMutex = (jMutexHandler != NULL_PTR) ? &callJLockMutex : NULL_PTR;

	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "UnlockMutex", CLASS_NAME(CLASS_UNLOCKMUTEX));
	assert(fieldID != 0);
	jMutexHandler = (*env)->GetObjectField(env, jInitArgs, fieldID);
  ckpInitArgs->UnlockMutex = (jMutexHandler != NULL_PTR) ? &callJUnlockMutex : NULL_PTR;

  if ((ckpInitArgs->CreateMutex != NULL_PTR)
      || (ckpInitArgs->DestroyMutex != NULL_PTR)
      || (ckpInitArgs->LockMutex != NULL_PTR)
      || (ckpInitArgs->UnlockMutex != NULL_PTR)) {
    /* we only need to keep a global copy, if we need callbacks */
    /* set the global object jInitArgs so that the right Java mutex functions will be called */
  	jInitArgsObject = (*env)->NewGlobalRef(env, jInitArgs);
    ckpGlobalInitArgs = (CK_C_INITIALIZE_ARGS_PTR) malloc(sizeof(CK_C_INITIALIZE_ARGS));
    if (ckpGlobalInitArgs == NULL_PTR) { free(ckpInitArgs); throwOutOfMemoryError(env); return NULL_PTR; }
    memcpy(ckpGlobalInitArgs, ckpInitArgs, sizeof(CK_C_INITIALIZE_ARGS));
  }
#endif /* NO_CALLBACKS */

	/* convert and set the flags field */
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "flags", "J");
	assert(fieldID != 0);
	jFlags = (*env)->GetLongField(env, jInitArgs, fieldID);
	ckpInitArgs->flags = jLongToCKULong(jFlags);

	/* pReserved should be NULL_PTR in this version */
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "pReserved", "Ljava/lang/Object;");
	assert(fieldID != 0);
	jReserved = (*env)->GetObjectField(env, jInitArgs, fieldID);

  /* we try to convert the reserved parameter also */
  jObjectToPrimitiveCKObjectPtrPtr(env, jReserved, &(ckpInitArgs->pReserved), &ckReservedLength, jUseUtf8);

	return ckpInitArgs ;
}

#ifndef NO_CALLBACKS

/*
 * is the function that gets called by PKCS#11 to create a mutex and calls the Java
 * CreateMutex function
 *
 * @param env - used to call JNI funktions to get the Java classes, objects, methods and fields
 * @param ppMutex - the new created mutex
 * @return - should return CKR_OK if the mutex creation was ok
 */
CK_RV callJCreateMutex(CK_VOID_PTR_PTR ppMutex)
{
  JavaVM *jvm;
  JNIEnv *env;
  jsize actualNumberVMs;
  jint returnValue;
  jthrowable pkcs11Exception;
  jclass pkcs11ExceptionClass;
  jlong errorCode;
  CK_RV rv = CKR_OK;
  int wasAttached = 1;
	jclass jCreateMutexClass;
	jclass jInitArgsClass;
	jmethodID methodID;
	jfieldID fieldID;
	jobject jCreateMutex;
	jobject jMutex;


  /* Get the currently running Java VM */
  returnValue = JNI_GetCreatedJavaVMs(&jvm, (jsize) 1, &actualNumberVMs);
  if ((returnValue != 0) || (actualNumberVMs <= 0)) { return rv ;} /* there is no VM running */

  /* Determine, if current thread is already attached */
  returnValue = (*jvm)->GetEnv(jvm, (void **) &env, JNI_VERSION_1_2);
  if (returnValue == JNI_EDETACHED) {
    /* thread detached, so attach it */
    wasAttached = 0;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else if (returnValue == JNI_EVERSION) {
    /* this version of JNI is not supported, so just try to attach */
    /* we assume it was attached to ensure that this thread is not detached
     * afterwards even though it should not
     */
    wasAttached = 1;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else {
    /* attached */
    wasAttached = 1;
  }


  jCreateMutexClass = (*env)->FindClass(env, CLASS_CREATEMUTEX);
	jInitArgsClass = (*env)->FindClass(env, CLASS_C_INITIALIZE_ARGS);

  /* get the CreateMutex object out of the jInitArgs object */
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "CreateMutex", CLASS_NAME(CLASS_CREATEMUTEX));
	assert(fieldID != 0);
	jCreateMutex = (*env)->GetObjectField(env, jInitArgsObject, fieldID);
	assert(jCreateMutex != 0);

	/* call the CK_CREATEMUTEX function of the CreateMutex object */
	/* and get the new Java mutex object */
	methodID = (*env)->GetMethodID(env, jCreateMutexClass, "CK_CREATEMUTEX", "()Ljava/lang/Object;");
	assert(methodID != 0);
	jMutex = (*env)->CallObjectMethod(env, jCreateMutex, methodID);

	/* set a global reference on the Java mutex */
	jMutex = (*env)->NewGlobalRef(env, jMutex);
	/* convert the Java mutex to a CK mutex */
	*ppMutex = jObjectToCKVoidPtr(jMutex);


  /* check, if callback threw an exception */
  pkcs11Exception = (*env)->ExceptionOccurred(env);

  if (pkcs11Exception != NULL_PTR) {
    /* The was an exception thrown, now we get the error-code from it */
    pkcs11ExceptionClass = (*env)->FindClass(env, CLASS_PKCS11EXCEPTION);
	  methodID = (*env)->GetMethodID(env, pkcs11ExceptionClass, "getErrorCode", "()J");
	  assert(methodID != 0);
    errorCode = (*env)->CallLongMethod(env, pkcs11Exception, methodID);
    rv = jLongToCKULong(errorCode);
  }

  /* if we attached this thread to the VM just for callback, we detach it now */
  if (wasAttached) {
    returnValue = (*jvm)->DetachCurrentThread(jvm);
  }

	return rv ;
}

/*
 * is the function that gets called by PKCS#11 to destroy a mutex and calls the Java
 * DestroyMutex function
 *
 * @param env - used to call JNI funktions to get the Java classes, objects, methods and fields
 * @param pMutex - the mutex to destroy
 * @return - should return CKR_OK if the mutex was destroyed
 */
CK_RV callJDestroyMutex(CK_VOID_PTR pMutex)
{
  JavaVM *jvm;
  JNIEnv *env;
  jsize actualNumberVMs;
  jint returnValue;
  jthrowable pkcs11Exception;
  jclass pkcs11ExceptionClass;
  jlong errorCode;
  CK_RV rv = CKR_OK;
  int wasAttached = 1;
	jclass jDestroyMutexClass;
	jclass jInitArgsClass;
	jmethodID methodID;
	jfieldID fieldID;
	jobject jDestroyMutex;
	jobject jMutex;


  /* Get the currently running Java VM */
  returnValue = JNI_GetCreatedJavaVMs(&jvm, (jsize) 1, &actualNumberVMs);
  if ((returnValue != 0) || (actualNumberVMs <= 0)) { return rv ; } /* there is no VM running */

  /* Determine, if current thread is already attached */
  returnValue = (*jvm)->GetEnv(jvm, (void **) &env, JNI_VERSION_1_2);
  if (returnValue == JNI_EDETACHED) {
    /* thread detached, so attach it */
    wasAttached = 0;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else if (returnValue == JNI_EVERSION) {
    /* this version of JNI is not supported, so just try to attach */
    /* we assume it was attached to ensure that this thread is not detached
     * afterwards even though it should not
     */
    wasAttached = 1;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else {
    /* attached */
    wasAttached = 1;
  }


  jDestroyMutexClass = (*env)->FindClass(env, CLASS_DESTROYMUTEX);
	jInitArgsClass = (*env)->FindClass(env, CLASS_C_INITIALIZE_ARGS);

  /* convert the CK mutex to a Java mutex */
	jMutex = ckVoidPtrToJObject(pMutex);

	/* get the DestroyMutex object out of the jInitArgs object */
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "DestroyMutex", CLASS_NAME(CLASS_DESTROYMUTEX));
	assert(fieldID != 0);
	jDestroyMutex = (*env)->GetObjectField(env, jInitArgsObject, fieldID);
	assert(jDestroyMutex != 0);

	/* call the CK_DESTROYMUTEX method of the DestroyMutex object */
	methodID = (*env)->GetMethodID(env, jDestroyMutexClass, "CK_DESTROYMUTEX", "(Ljava/lang/Object;)V");
	assert(methodID != 0);
	(*env)->CallVoidMethod(env, jDestroyMutex, methodID, jMutex);

	/* delete the global reference on the Java mutex */
	(*env)->DeleteGlobalRef(env, jMutex);


  /* check, if callback threw an exception */
  pkcs11Exception = (*env)->ExceptionOccurred(env);

  if (pkcs11Exception != NULL_PTR) {
    /* The was an exception thrown, now we get the error-code from it */
    pkcs11ExceptionClass = (*env)->FindClass(env, CLASS_PKCS11EXCEPTION);
	  methodID = (*env)->GetMethodID(env, pkcs11ExceptionClass, "getErrorCode", "()J");
	  assert(methodID != 0);
    errorCode = (*env)->CallLongMethod(env, pkcs11Exception, methodID);
    rv = jLongToCKULong(errorCode);
  }

  /* if we attached this thread to the VM just for callback, we detach it now */
  if (wasAttached) {
    returnValue = (*jvm)->DetachCurrentThread(jvm);
  }

	return rv ;
}

/*
 * is the function that gets called by PKCS#11 to lock a mutex and calls the Java
 * LockMutex function
 *
 * @param env - used to call JNI funktions to get the Java classes, objects, methods and fields
 * @param pMutex - the mutex to lock
 * @return - should return CKR_OK if the mutex was not locked already
 */
CK_RV callJLockMutex(CK_VOID_PTR pMutex)
{
  JavaVM *jvm;
  JNIEnv *env;
  jsize actualNumberVMs;
  jint returnValue;
  jthrowable pkcs11Exception;
  jclass pkcs11ExceptionClass;
  jlong errorCode;
  CK_RV rv = CKR_OK;
  int wasAttached = 1;
	jclass jLockMutexClass;
	jclass jInitArgsClass;
	jmethodID methodID;
	jfieldID fieldID;
	jobject jLockMutex;
	jobject jMutex;


  /* Get the currently running Java VM */
  returnValue = JNI_GetCreatedJavaVMs(&jvm, (jsize) 1, &actualNumberVMs);
  if ((returnValue != 0) || (actualNumberVMs <= 0)) { return rv ; } /* there is no VM running */

  /* Determine, if current thread is already attached */
  returnValue = (*jvm)->GetEnv(jvm, (void **) &env, JNI_VERSION_1_2);
  if (returnValue == JNI_EDETACHED) {
    /* thread detached, so attach it */
    wasAttached = 0;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else if (returnValue == JNI_EVERSION) {
    /* this version of JNI is not supported, so just try to attach */
    /* we assume it was attached to ensure that this thread is not detached
     * afterwards even though it should not
     */
    wasAttached = 1;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else {
    /* attached */
    wasAttached = 1;
  }


  jLockMutexClass = (*env)->FindClass(env, CLASS_LOCKMUTEX);
	jInitArgsClass = (*env)->FindClass(env, CLASS_C_INITIALIZE_ARGS);

  /* convert the CK mutex to a Java mutex */
	jMutex = ckVoidPtrToJObject(pMutex);

	/* get the LockMutex object out of the jInitArgs object */
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "LockMutex", CLASS_NAME(CLASS_LOCKMUTEX));
	assert(fieldID != 0);
	jLockMutex = (*env)->GetObjectField(env, jInitArgsObject, fieldID);
	assert(jLockMutex != 0);

	/* call the CK_LOCKMUTEX method of the LockMutex object */
	methodID = (*env)->GetMethodID(env, jLockMutexClass, "CK_LOCKMUTEX", "(Ljava/lang/Object;)V");
	assert(methodID != 0);
	(*env)->CallVoidMethod(env, jLockMutex, methodID, jMutex);


  /* check, if callback threw an exception */
  pkcs11Exception = (*env)->ExceptionOccurred(env);

  if (pkcs11Exception != NULL_PTR) {
    /* The was an exception thrown, now we get the error-code from it */
    pkcs11ExceptionClass = (*env)->FindClass(env, CLASS_PKCS11EXCEPTION);
	  methodID = (*env)->GetMethodID(env, pkcs11ExceptionClass, "getErrorCode", "()J");
	  assert(methodID != 0);
    errorCode = (*env)->CallLongMethod(env, pkcs11Exception, methodID);
    rv = jLongToCKULong(errorCode);
  }

  /* if we attached this thread to the VM just for callback, we detach it now */
  if (wasAttached) {
    returnValue = (*jvm)->DetachCurrentThread(jvm);
  }

	return rv ;
}

/*
 * is the function that gets called by PKCS#11 to unlock a mutex and calls the Java
 * UnlockMutex function
 *
 * @param env - used to call JNI funktions to get the Java classes, objects, methods and fields
 * @param pMutex - the mutex to unlock
 * @return - should return CKR_OK if the mutex was not unlocked already
 */
CK_RV callJUnlockMutex(CK_VOID_PTR pMutex)
{
  JavaVM *jvm;
  JNIEnv *env;
  jsize actualNumberVMs;
  jint returnValue;
  jthrowable pkcs11Exception;
  jclass pkcs11ExceptionClass;
  jlong errorCode;
  CK_RV rv = CKR_OK;
  int wasAttached = 1;
	jclass jUnlockMutexClass;
	jclass jInitArgsClass;
	jmethodID methodID;
	jfieldID fieldID;
	jobject jUnlockMutex;
	jobject jMutex;


  /* Get the currently running Java VM */
  returnValue = JNI_GetCreatedJavaVMs(&jvm, (jsize) 1, &actualNumberVMs);
  if ((returnValue != 0) || (actualNumberVMs <= 0)) { return rv ; } /* there is no VM running */

  /* Determine, if current thread is already attached */
  returnValue = (*jvm)->GetEnv(jvm, (void **) &env, JNI_VERSION_1_2);
  if (returnValue == JNI_EDETACHED) {
    /* thread detached, so attach it */
    wasAttached = 0;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else if (returnValue == JNI_EVERSION) {
    /* this version of JNI is not supported, so just try to attach */
    /* we assume it was attached to ensure that this thread is not detached
     * afterwards even though it should not
     */
    wasAttached = 1;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else {
    /* attached */
    wasAttached = 1;
  }


  jUnlockMutexClass = (*env)->FindClass(env, CLASS_UNLOCKMUTEX);
	jInitArgsClass = (*env)->FindClass(env, CLASS_C_INITIALIZE_ARGS);

  /* convert the CK-type mutex to a Java mutex */
	jMutex = ckVoidPtrToJObject(pMutex);

	/* get the UnlockMutex object out of the jInitArgs object */
	fieldID = (*env)->GetFieldID(env, jInitArgsClass, "UnlockMutex", CLASS_NAME(CLASS_UNLOCKMUTEX));
	assert(fieldID != 0);
	jUnlockMutex = (*env)->GetObjectField(env, jInitArgsObject, fieldID);
	assert(jUnlockMutex != 0);

	/* call the CK_UNLOCKMUTEX method of the UnLockMutex object */
	methodID = (*env)->GetMethodID(env, jUnlockMutexClass, "CK_UNLOCKMUTEX", "(Ljava/lang/Object;)V");
	assert(methodID != 0);
	(*env)->CallVoidMethod(env, jUnlockMutex, methodID, jMutex);


  /* check, if callback threw an exception */
  pkcs11Exception = (*env)->ExceptionOccurred(env);

  if (pkcs11Exception != NULL_PTR) {
    /* The was an exception thrown, now we get the error-code from it */
    pkcs11ExceptionClass = (*env)->FindClass(env, CLASS_PKCS11EXCEPTION);
	  methodID = (*env)->GetMethodID(env, pkcs11ExceptionClass, "getErrorCode", "()J");
	  assert(methodID != 0);
    errorCode = (*env)->CallLongMethod(env, pkcs11Exception, methodID);
    rv = jLongToCKULong(errorCode);
  }

  /* if we attached this thread to the VM just for callback, we detach it now */
  if (wasAttached) {
    returnValue = (*jvm)->DetachCurrentThread(jvm);
  }

	return rv ;
}


/*
 * The function handling notify callbacks. It casts the pApplication paramter
 * back to a NotifyEncapsulation structure and retrieves the Notify object and
 * the application data from it.
 *
 * @param hSession The session, this callback is comming from.
 * @param event The type of event that occurred.
 * @param pApplication The application data as passed in upon OpenSession. In
                       this wrapper we always pass in a NotifyEncapsulation
                       object, which holds necessary information for delegating
                       the callback to the Java VM.
 * @return
 */
CK_RV notifyCallback(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
)
{
	NotifyEncapsulation *notifyEncapsulation;
  JavaVM *jvm;
  JNIEnv *env;
  jsize actualNumberVMs;
  jint returnValue;
  jlong jSessionHandle;
  jlong jEvent;
  jclass ckNotifyClass;
  jmethodID jmethod;
  jthrowable pkcs11Exception;
  jclass pkcs11ExceptionClass;
  jlong errorCode;
  CK_RV rv = CKR_OK;
  int wasAttached = 1;

  if (pApplication == NULL_PTR) { return rv ; } /* This should not occur in this wrapper. */

  notifyEncapsulation = (NotifyEncapsulation *) pApplication;

  /* Get the currently running Java VM */
  returnValue = JNI_GetCreatedJavaVMs(&jvm, (jsize) 1, &actualNumberVMs);
  if ((returnValue != 0) || (actualNumberVMs <= 0)) { return rv ; } /* there is no VM running */

  /* Determine, if current thread is already attached */
  returnValue = (*jvm)->GetEnv(jvm, (void **) &env, JNI_VERSION_1_2);
  if (returnValue == JNI_EDETACHED) {
    /* thread detached, so attach it */
    wasAttached = 0;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else if (returnValue == JNI_EVERSION) {
    /* this version of JNI is not supported, so just try to attach */
    /* we assume it was attached to ensure that this thread is not detached
     * afterwards even though it should not
     */
    wasAttached = 1;
    returnValue = (*jvm)->AttachCurrentThread(jvm, (void **) &env, NULL_PTR);
  } else {
    /* attached */
    wasAttached = 1;
  }

  jSessionHandle = ckULongToJLong(hSession);
  jEvent = ckULongToJLong(event);

	ckNotifyClass = (*env)->FindClass(env, CLASS_NOTIFY);
	assert(ckNotifyClass != 0);
	jmethod = (*env)->GetMethodID(env, ckNotifyClass, "CK_NOTIFY", "(JJLjava/lang/Object;)V");
	assert(jmethod != 0);
  (*env)->CallVoidMethod(env, notifyEncapsulation->jNotifyObject, jmethod,
                         jSessionHandle, jEvent, notifyEncapsulation->jApplicationData);

  /* check, if callback threw an exception */
  pkcs11Exception = (*env)->ExceptionOccurred(env);

  if (pkcs11Exception != NULL_PTR) {
    /* The was an exception thrown, now we get the error-code from it */
    pkcs11ExceptionClass = (*env)->FindClass(env, CLASS_PKCS11EXCEPTION);
	  jmethod = (*env)->GetMethodID(env, pkcs11ExceptionClass, "getErrorCode", "()J");
	  assert(jmethod != 0);
    errorCode = (*env)->CallLongMethod(env, pkcs11Exception, jmethod);
    rv = jLongToCKULong(errorCode);
  }

  /* if we attached this thread to the VM just for callback, we detach it now */
  if (wasAttached) {
    returnValue = (*jvm)->DetachCurrentThread(jvm);
  }

	return rv ;
}

#endif /* NO_CALLBACKS */


/* ************************************************************************** */
/* Below there follow the helper functions to support conversions between     */
/* Java and Cryptoki types                                                    */
/* ************************************************************************** */

/*
 * function to convert a PKCS#11 return value into a PKCS#11Exception
 *
 * This function generates a PKCS#11Exception with the returnValue as the errorcode
 * if the returnValue is not CKR_OK. The functin returns 0, if the returnValue is
 * CKR_OK. Otherwise, it returns the returnValue as a jLong.
 *
 * @param env - used to call JNI funktions and to get the Exception class
 * @param returnValue - of the PKCS#11 function
 */
jlong ckAssertReturnValueOK(JNIEnv *env, CK_RV returnValue, const char* callerMethodName)
{
	jclass jPKCS11ExceptionClass;
	jmethodID jConstructor;
	jthrowable jPKCS11Exception;
	jlong jErrorCode;

	if (returnValue == CKR_OK) {
		return 0L ;
	} else {
		jPKCS11ExceptionClass = (*env)->FindClass(env, CLASS_PKCS11EXCEPTION);
		assert(jPKCS11ExceptionClass != 0);
		jConstructor = (*env)->GetMethodID(env, jPKCS11ExceptionClass, "<init>", "(J)V");
		assert(jConstructor != 0);
		jErrorCode = ckULongToJLong(returnValue);
		jPKCS11Exception = (jthrowable) (*env)->NewObject(env, jPKCS11ExceptionClass, jConstructor, jErrorCode);
		(*env)->Throw(env, jPKCS11Exception);
		TRACE1(tag_error, callerMethodName, "got %lu instead of CKR_OK, going to raise an exception", returnValue);
		return jErrorCode ;
	}
}

/*
 * this function throws an OutOfMemoryError, e.g. in case a malloc did fail to
 * allocate memory.
 *
 * @param env Used to call JNI funktions and to get the Exception class.
 */
void throwOutOfMemoryError(JNIEnv *env)
{
	jclass jOutOfMemoryErrorClass;
	jmethodID jConstructor;
	jthrowable jOutOfMemoryError;

	jOutOfMemoryErrorClass = (*env)->FindClass(env, CLASS_OUT_OF_MEMORY_ERROR);
	assert(jOutOfMemoryErrorClass != 0);

	jConstructor = (*env)->GetMethodID(env, jOutOfMemoryErrorClass, "<init>", "()V");
	assert(jConstructor != 0);
	jOutOfMemoryError = (jthrowable) (*env)->NewObject(env, jOutOfMemoryErrorClass, jConstructor);
	(*env)->Throw(env, jOutOfMemoryError);
}

/*
 * this function simply throws a FileNotFoundException
 *
 * @param env Used to call JNI funktions and to get the Exception class.
 * @param jmessage The message string of the Exception object.
 */
void throwFileNotFoundException(JNIEnv *env, jstring jmessage)
{
	jclass jFileNotFoundExceptionClass;
	jmethodID jConstructor;
	jthrowable jFileNotFoundException;

	jFileNotFoundExceptionClass = (*env)->FindClass(env, CLASS_FILE_NOT_FOUND_EXCEPTION);
	assert(jFileNotFoundExceptionClass != 0);

	jConstructor = (*env)->GetMethodID(env, jFileNotFoundExceptionClass, "<init>", "(Ljava/lang/String;)V");
	assert(jConstructor != 0);
	jFileNotFoundException = (jthrowable) (*env)->NewObject(env, jFileNotFoundExceptionClass, jConstructor, jmessage);
	(*env)->Throw(env, jFileNotFoundException);
}

/*
 * this function simply throws an IOException
 *
 * @param env Used to call JNI funktions and to get the Exception class.
 * @param message The message string of the Exception object.
 */
void throwIOException(JNIEnv *env, const char * message)
{
	jclass jIOExceptionClass;

	jIOExceptionClass = (*env)->FindClass(env, CLASS_IO_EXCEPTION);
	assert(jIOExceptionClass != 0);

  (*env)->ThrowNew(env, jIOExceptionClass, message);
}

/*
 * this function simply throws an IOException and takes a unicode
 * messge.
 *
 * @param env Used to call JNI funktions and to get the Exception class.
 * @param message The unicode message string of the Exception object.
 */
void throwIOExceptionUnicodeMessage(JNIEnv *env, const unsigned short *message)
{
	jclass jIOExceptionClass;
	jmethodID jConstructor;
	jthrowable jIOException;
  jstring jmessage;
  jsize length;
  short *currentCharacter;

	jIOExceptionClass = (*env)->FindClass(env, CLASS_IO_EXCEPTION);
	assert(jIOExceptionClass != 0);

  length = 0;
  if (message != NULL_PTR) {
    currentCharacter = (short *) message;
    while (*(currentCharacter++) != 0) length++;
  }

  jmessage = (*env)->NewString(env, message, length);

	jConstructor = (*env)->GetMethodID(env, jIOExceptionClass, "<init>", "(Ljava/lang/String;)V");
	assert(jConstructor != 0);
	jIOException = (jthrowable) (*env)->NewObject(env, jIOExceptionClass, jConstructor, jmessage);
	(*env)->Throw(env, jIOException);
}

/*
 * This function simply throws a PKCS#11RuntimeException with the given
 * string as its message. If the message is NULL_PTR, the exception is created
 * using the default constructor.
 *
 * @param env Used to call JNI funktions and to get the Exception class.
 * @param jmessage The message string of the Exception object.
 */
void throwPKCS11RuntimeException(JNIEnv *env, jstring jmessage)
{
	jclass jPKCS11RuntimeExceptionClass;
	jmethodID jConstructor;
	jthrowable jPKCS11RuntimeException;

	jPKCS11RuntimeExceptionClass = (*env)->FindClass(env, CLASS_PKCS11RUNTIMEEXCEPTION);
	assert(jPKCS11RuntimeExceptionClass != 0);

  if (jmessage == NULL_PTR) {
	  jConstructor = (*env)->GetMethodID(env, jPKCS11RuntimeExceptionClass, "<init>", "()V");
	  assert(jConstructor != 0);
	  jPKCS11RuntimeException = (jthrowable) (*env)->NewObject(env, jPKCS11RuntimeExceptionClass, jConstructor);
	  (*env)->Throw(env, jPKCS11RuntimeException);
  } else {
	  jConstructor = (*env)->GetMethodID(env, jPKCS11RuntimeExceptionClass, "<init>", "(Ljava/lang/String;)V");
	  assert(jConstructor != 0);
	  jPKCS11RuntimeException = (jthrowable) (*env)->NewObject(env, jPKCS11RuntimeExceptionClass, jConstructor, jmessage);
	  (*env)->Throw(env, jPKCS11RuntimeException);
  }
}

/*
 * This function simply throws a PKCS#11RuntimeException. The message says that
 * the object is not connected to the module.
 *
 * @param env Used to call JNI funktions and to get the Exception class.
 */
void throwDisconnectedRuntimeException(JNIEnv *env)
{
	jstring jExceptionMessage = (*env)->NewStringUTF(env, "This object is not connected to a module.");

  throwPKCS11RuntimeException(env, jExceptionMessage);
}

/*
 * the following functions convert Java arrays to PKCS#11 array pointers and
 * their array length and vice versa
 *
 * void j<Type>ArrayToCK<Type>Array(JNIEnv *env,
 *                                  const j<Type>Array jArray,
 *                                  CK_<Type>_PTR *ckpArray,
 *                                  CK_ULONG_PTR ckLength);
 *
 * j<Type>Array ck<Type>ArrayToJ<Type>Array(JNIEnv *env,
 *                                          const CK_<Type>_PTR ckpArray,
 *                                          CK_ULONG ckLength);
 *
 * PKCS#11 arrays consist always of a pointer to the beginning of the array and
 * the array length whereas Java arrays carry their array length.
 *
 * The Functions to convert a Java array to a PKCS#11 array are void functions.
 * Their arguments are the Java array object to convert, the reference to the
 * array pointer, where the new PKCS#11 array should be stored and the reference
 * to the array length where the PKCS#11 array length should be stored. These two
 * references must not be NULL_PTR.
 *
 * The functions first obtain the array length of the Java array and then allocate
 * the memory for the PKCS#11 array and set the array length. Then each element
 * gets converted depending on their type. After use the allocated memory of the
 * PKCS#11 array has to be explicitly freed.
 *
 * The Functions to convert a PKCS#11 array to a Java array get the PKCS#11 array
 * pointer and the array length and they return the new Java array object. The
 * Java array does not need to get freed after use.
 */

/*
 * converts a jbooleanArray to a CK_BBOOL array. The allocated memory has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_BBOOL array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jBooleanArrayToCKBBoolArray(JNIEnv *env, const jbooleanArray jArray, CK_BBOOL **ckpArray, CK_ULONG_PTR ckpLength)
{
	jboolean* jpTemp;
	CK_ULONG i;

	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}
	*ckpLength = (*env)->GetArrayLength(env, jArray);
	jpTemp = (jboolean*) malloc((*ckpLength) * sizeof(jboolean));
  if (jpTemp == NULL_PTR && (*ckpLength)!=0) { *ckpArray = NULL_PTR; throwOutOfMemoryError(env); return 1; }
	(*env)->GetBooleanArrayRegion(env, jArray, 0, *ckpLength, jpTemp);
	*ckpArray = (CK_BBOOL*) malloc ((*ckpLength) * sizeof(CK_BBOOL));
  if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { free(jpTemp); throwOutOfMemoryError(env); return 2; }
	for (i=0; i<(*ckpLength); i++) {
		(*ckpArray)[i] = jBooleanToCKBBool(jpTemp[i]);
	}
	free(jpTemp);
  return 0;
}

/*
 * converts a jbyteArray to a CK_BYTE array. The allocated memory has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_BYTE array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jByteArrayToCKByteArray(JNIEnv *env, const jbyteArray jArray, CK_BYTE_PTR *ckpArray, CK_ULONG_PTR ckpLength)
{
	jbyte* jpTemp;
	CK_ULONG i;

	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}
	*ckpLength = (*env)->GetArrayLength(env, jArray);
	jpTemp = (jbyte*) malloc((*ckpLength) * sizeof(jbyte));
  if (jpTemp == NULL_PTR && (*ckpLength)!=0) { *ckpArray = NULL_PTR; throwOutOfMemoryError(env); return 1; }
	(*env)->GetByteArrayRegion(env, jArray, 0, *ckpLength, jpTemp);

  /* if CK_BYTE is the same size as jbyte, we save an additional copy */
  if (sizeof(CK_BYTE) == sizeof(jbyte)) {
    *ckpArray = (CK_BYTE_PTR) jpTemp;
  } else {
	  *ckpArray = (CK_BYTE_PTR) malloc ((*ckpLength) * sizeof(CK_BYTE));
    if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { free(jpTemp); throwOutOfMemoryError(env); return 2; }
	  for (i=0; i<(*ckpLength); i++) {
		  (*ckpArray)[i] = jByteToCKByte(jpTemp[i]);
	  }
	  free(jpTemp);
  }
  return 0;
}

/*
 * converts a jlongArray to a CK_ULONG array. The allocated memory has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_ULONG array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jLongArrayToCKULongArray(JNIEnv *env, const jlongArray jArray, CK_ULONG_PTR *ckpArray, CK_ULONG_PTR ckpLength)
{
	jlong* jpTemp;
	CK_ULONG i;

	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}
	*ckpLength = (*env)->GetArrayLength(env, jArray);
	jpTemp = (jlong*) malloc((*ckpLength) * sizeof(jlong));
  if (jpTemp == NULL_PTR && (*ckpLength)!=0) { *ckpArray = NULL_PTR; throwOutOfMemoryError(env); return 1; }
	(*env)->GetLongArrayRegion(env, jArray, 0, *ckpLength, jpTemp);
	*ckpArray = (CK_ULONG_PTR) malloc (*ckpLength * sizeof(CK_ULONG));
  if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { free(jpTemp); throwOutOfMemoryError(env); return 2; }
	for (i=0; i<(*ckpLength); i++) {
		(*ckpArray)[i] = jLongToCKULong(jpTemp[i]);
	}
	free(jpTemp);
	return 0;
}

/*
 * converts a jcharArray to a CK_CHAR array. The allocated memory has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_CHAR array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jCharArrayToCKCharArray(JNIEnv *env, const jcharArray jArray, CK_CHAR_PTR *ckpArray, CK_ULONG_PTR ckpLength)
{

	jchar* jpTemp;
	CK_ULONG i;

	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}

	TRACE0(tag_call, __FUNCTION__, "entering");
	*ckpLength = (*env)->GetArrayLength(env, jArray);
	jpTemp = (jchar*) malloc((*ckpLength) * sizeof(jchar));
  if (jpTemp == NULL_PTR && (*ckpLength)!=0) { *ckpArray = NULL_PTR; throwOutOfMemoryError(env); return 1; }
	(*env)->GetCharArrayRegion(env, jArray, 0, *ckpLength, jpTemp);
	*ckpArray = (CK_CHAR_PTR) malloc (*ckpLength * sizeof(CK_CHAR));
  if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { free(jpTemp); throwOutOfMemoryError(env); return 2; }
	for (i=0; i<(*ckpLength); i++) {
		(*ckpArray)[i] = jCharToCKChar(jpTemp[i]);
	}
	free(jpTemp);
	TRACE0(tag_call, __FUNCTION__, "exiting ");
  return 0;
}

/*
 * converts a jcharArray to a CK_UTF8CHAR array. The allocated memory has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_UTF8CHAR array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jCharArrayToCKUTF8CharArray(JNIEnv *env, const jcharArray jArray, CK_UTF8CHAR_PTR *ckpArray, CK_ULONG_PTR ckpLength)
{
	jbyte* jpTemp;
	CK_ULONG i;
	jclass jStringEncoderClass;
	jmethodID jEncoderMethod;
	jbyteArray jValue;

	TRACE0(tag_call, __FUNCTION__, "entering");
	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}
	jStringEncoderClass = (*env)->FindClass(env, CLASS_PKCS11UTIL);
	assert(jStringEncoderClass != 0);
	jEncoderMethod = (*env)->GetStaticMethodID(env, jStringEncoderClass, METHOD_ENCODER, "([C)[B");
	assert(jEncoderMethod != 0);
	jValue = (*env)->CallStaticObjectMethod(env, jStringEncoderClass, jEncoderMethod, jArray);
	if(jValue == 0)
		return 1;
	*ckpLength = (*env)->GetArrayLength(env, jValue);
	jpTemp = (jbyte*) malloc((*ckpLength) * sizeof(jbyte));
  if (jpTemp == NULL_PTR && (*ckpLength)!=0) { *ckpArray = NULL_PTR; throwOutOfMemoryError(env); return 1; }
	(*env)->GetByteArrayRegion(env, jValue, 0, *ckpLength, jpTemp);
	*ckpArray = (CK_UTF8CHAR_PTR) malloc (*ckpLength * sizeof(CK_UTF8CHAR));
  if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { free(jpTemp); throwOutOfMemoryError(env); return 2; }
	for (i=0; i<(*ckpLength); i++) {
		(*ckpArray)[i] = jByteToCKUTF8Char(jpTemp[i]);
	}
	free(jpTemp);
	TRACE0(tag_call, __FUNCTION__, "exiting ");
  return 0;
}

/*
 * converts a jstring to a CK_CHAR array. The allocated memory has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_CHAR array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jStringToCKUTF8CharArray(JNIEnv *env, const jstring jArray, CK_UTF8CHAR_PTR *ckpArray, CK_ULONG_PTR ckpLength)
{
	const char* pCharArray;
	jboolean isCopy;

	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}

	pCharArray = (*env)->GetStringUTFChars(env, jArray, &isCopy);
	*ckpLength = strlen(pCharArray);
	*ckpArray = (CK_UTF8CHAR_PTR) malloc((*ckpLength + 1) * sizeof(CK_UTF8CHAR));
  if (*ckpArray == NULL_PTR && (*ckpLength + 1)!=0) { throwOutOfMemoryError(env); return 1; }
	strcpy((char *) *ckpArray, pCharArray);
	(*env)->ReleaseStringUTFChars(env, (jstring) jArray, pCharArray);
  return 0;
}

/*
 * converts a jobjectArray with Java Attributes to a CK_ATTRIBUTE array. The allocated memory
 * has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java Attribute array (template) to convert
 * @param ckpArray - the reference, where the pointer to the new CK_ATTRIBUTE array will be
 *                   stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
int jAttributeArrayToCKAttributeArray(JNIEnv *env, jobjectArray jArray, CK_ATTRIBUTE_PTR *ckpArray, CK_ULONG_PTR ckpLength, jboolean jUseUtf8)
{
	CK_ULONG i;
	jlong jLength;
	jobject jAttribute;

	TRACE0(tag_call, __FUNCTION__,"entering");
	if (jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
	  TRACE0(tag_call, __FUNCTION__, "exiting ");
		return 0;
	}
	jLength = (*env)->GetArrayLength(env, jArray);
	*ckpLength = jLongToCKULong(jLength);
	TRACE1(tag_debug, __FUNCTION__, "array length is %ld", *ckpLength)
	*ckpArray = (CK_ATTRIBUTE_PTR) malloc(*ckpLength * sizeof(CK_ATTRIBUTE));
  if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { throwOutOfMemoryError(env); return 1; }
	TRACE1(tag_debug, __FUNCTION__,"converting %lld attributes", jLength);
	for (i=0; i<(*ckpLength); i++) {
		TRACE1(tag_debug, __FUNCTION__,", getting %ld. attribute", i);
		jAttribute = (*env)->GetObjectArrayElement(env, jArray, i);
		TRACE2(tag_debug, __FUNCTION__,", jAttribute = %p, converting %ld. attribute", jAttribute, i);
		(*ckpArray)[i] = jAttributeToCKAttribute(env, jAttribute, jUseUtf8);
	}
	TRACE0(tag_debug, __FUNCTION__,"Converted template with following types: ");
	for (i=0; i<(*ckpLength); i++) {
		TRACE1(tag_debug, __FUNCTION__,"0x%lX", (*ckpArray)[i].type);
	}
  TRACE0(tag_call, __FUNCTION__, "exiting ");
  return 0;
}

/*
 * converts a jobjectArray to a CK_VOID_PTR array. The allocated memory has to be freed after
 * use!
 * NOTE: this function does not work and is not used yet
 *
 * @param env - used to call JNI funktions to get the array informtaion
 * @param jArray - the Java object array to convert
 * @param ckpArray - the reference, where the pointer to the new CK_VOID_PTR array will be stored
 * @param ckpLength - the reference, where the array length will be stored
 * @return 0 is successful
 */
/*
int jObjectArrayToCKVoidPtrArray(JNIEnv *env, const jobjectArray jArray, CK_VOID_PTR_PTR *ckpArray, CK_ULONG_PTR ckpLength)
{
	jobject jTemp;
	CK_ULONG i;

	if(jArray == NULL_PTR) {
		*ckpArray = NULL_PTR;
		*ckpLength = 0L;
		return 0;
	}
	*ckpLength = (*env)->GetArrayLength(env, jArray);
	*ckpArray = (CK_VOID_PTR_PTR) malloc (*ckpLength * sizeof(CK_VOID_PTR));
  if (*ckpArray == NULL_PTR && (*ckpLength)!=0) { throwOutOfMemoryError(env); return 1; }
	for (i=0; i<(*ckpLength); i++) {
		jTemp = (*env)->GetObjectArrayElement(env, jArray, i);
		(*ckpArray)[i] = jObjectToCKVoidPtr(jTemp);
	}
	free(jTemp);
  return 0;
}
*/

/*
 * converts a CK_BYTE array and its length to a jbyteArray.
 *
 * @param env - used to call JNI funktions to create the new Java array
 * @param ckpArray - the pointer to the CK_BYTE array to convert
 * @param ckpLength - the length of the array to convert
 * @return - the new Java byte array
 */
jbyteArray ckByteArrayToJByteArray(JNIEnv *env, const CK_BYTE_PTR ckpArray, CK_ULONG ckLength)
{
	CK_ULONG i;
	jbyte* jpTemp;
	jbyteArray jArray;

  /* if CK_BYTE is the same size as jbyte, we save an additional copy */
  if (sizeof(CK_BYTE) == sizeof(jbyte)) {
    jpTemp = (jbyte*) ckpArray;
  } else {
	  jpTemp = (jbyte*) malloc((ckLength) * sizeof(jbyte));
    if (jpTemp == NULL_PTR && ckLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }
	  for (i=0; i<ckLength; i++) {
		  jpTemp[i] = ckByteToJByte(ckpArray[i]);
	  }
  }

	jArray = (*env)->NewByteArray(env, ckULongToJSize(ckLength));
	(*env)->SetByteArrayRegion(env, jArray, 0, ckULongToJSize(ckLength), jpTemp);

  if (sizeof(CK_BYTE) != sizeof(jbyte)) {
    free(jpTemp);
  }

	return jArray ;
}

/*
 * converts a CK_ULONG array and its length to a jlongArray.
 *
 * @param env - used to call JNI funktions to create the new Java array
 * @param ckpArray - the pointer to the CK_ULONG array to convert
 * @param ckpLength - the length of the array to convert
 * @return - the new Java long array
 */
jlongArray ckULongArrayToJLongArray(JNIEnv *env, const CK_ULONG_PTR ckpArray, CK_ULONG ckLength)
{
	CK_ULONG i;
	jlong* jpTemp;
	jlongArray jArray;

	jpTemp = (jlong*) malloc((ckLength) * sizeof(jlong));
  if (jpTemp == NULL_PTR && ckLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }
	for (i=0; i<ckLength; i++) {
		jpTemp[i] = ckLongToJLong(ckpArray[i]);
	}
	jArray = (*env)->NewLongArray(env, ckULongToJSize(ckLength));
	(*env)->SetLongArrayRegion(env, jArray, 0, ckULongToJSize(ckLength), jpTemp);
	free(jpTemp);

	return jArray ;
}

/*
 * converts a CK_CHAR array and its length to a jcharArray.
 *
 * @param env - used to call JNI funktions to create the new Java array
 * @param ckpArray - the pointer to the CK_CHAR array to convert
 * @param ckpLength - the length of the array to convert
 * @return - the new Java char array
 */
jcharArray ckCharArrayToJCharArray(JNIEnv *env, const CK_CHAR_PTR ckpArray, CK_ULONG ckLength)
{
	CK_ULONG i;
	jchar* jpTemp;
	jcharArray jArray;

	TRACE0(tag_call, __FUNCTION__, "entering");
	jpTemp = (jchar*) malloc(ckLength * sizeof(jchar));
  if (jpTemp == NULL_PTR && ckLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }
	for (i=0; i<ckLength; i++) {
		jpTemp[i] = ckCharToJChar(ckpArray[i]);
	}
	jArray = (*env)->NewCharArray(env, ckULongToJSize(ckLength));
	(*env)->SetCharArrayRegion(env, jArray, 0, ckULongToJSize(ckLength), jpTemp);
	free(jpTemp);

	TRACE0(tag_call, __FUNCTION__, "exiting");
	return jArray ;
}

/*
 * converts a CK_UTF8CHAR array and its length to a jcharArray.
 *
 * @param env - used to call JNI funktions to create the new Java array
 * @param ckpArray - the pointer to the CK_UTF8CHAR array to convert
 * @param ckpLength - the length of the array to convert
 * @return - the new Java char array
 */
jcharArray ckUTF8CharArrayToJCharArray(JNIEnv *env, const CK_UTF8CHAR_PTR ckpArray, CK_ULONG ckLength)
{

	CK_ULONG i;
	jbyte* jpTemp;
	jbyteArray jArray;
	jclass jStringDecoderClass;
	jmethodID jDecoderMethod;
	jcharArray jValue;

	TRACE0(tag_call, __FUNCTION__, "entering");
	jpTemp = (jbyte*) malloc(ckLength * sizeof(jbyte));
  if (jpTemp == NULL_PTR && ckLength!=0) { throwOutOfMemoryError(env); return NULL_PTR; }
	for (i=0; i<ckLength; i++) {
		jpTemp[i] = ckUTF8CharToJByte(ckpArray[i]);
	}
	jArray = (*env)->NewByteArray(env, ckULongToJSize(ckLength));
	(*env)->SetByteArrayRegion(env, jArray, 0, ckULongToJSize(ckLength), jpTemp);

	jStringDecoderClass = (*env)->FindClass(env, CLASS_PKCS11UTIL);
	assert(jStringDecoderClass != 0);
	jDecoderMethod = (*env)->GetStaticMethodID(env, jStringDecoderClass, METHOD_DECODER, "([B)[C");
	assert(jDecoderMethod != 0);
	jValue = (*env)->CallStaticObjectMethod(env, jStringDecoderClass, jDecoderMethod, jArray);

	free(jpTemp);

	TRACE0(tag_call, __FUNCTION__, "exiting");
	return jValue ;
}

jobject ckAttributeArrayToJAttributeArray(JNIEnv *env, const CK_ATTRIBUTE_PTR ckpArray, CK_ULONG ckLength, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jboolean jUseUtf8)
{
	jclass jAttributeClass;
	jobjectArray jAttributeArray;
	CK_ULONG i;
	CK_ULONG length;
	jobject jAttribute;
	jsize jlength;

	length = ckLength/sizeof(CK_ATTRIBUTE);
	jlength = ckULongToJSize(length);
	jAttributeClass = (*env)->FindClass(env, CLASS_ATTRIBUTE);
	assert(jAttributeClass != 0);
	/* allocate array, all elements NULL_PTR per default */
	jAttributeArray = (*env)->NewObjectArray(env, jlength, jAttributeClass, NULL_PTR);
	assert(jAttributeArray != 0);

	for (i=0; i<length; i++) {
		jAttribute = ckAttributePtrToJAttribute(env, &(ckpArray[i]), obj, jSessionHandle, jObjectHandle, jUseUtf8);
		(*env)->SetObjectArrayElement(env, jAttributeArray, i, jAttribute);
	}

	return jAttributeArray ;
}

/*
 * the following functions convert Java objects to PKCS#11 pointers and the
 * length in bytes and vice versa
 *
 * CK_<Type>_PTR j<Object>ToCK<Type>Ptr(JNIEnv *env, jobject jObject);
 *
 * jobject ck<Type>PtrToJ<Object>(JNIEnv *env, const CK_<Type>_PTR ckpValue);
 *
 * The functions that convert a Java object to a PKCS#11 pointer first allocate
 * the memory for the PKCS#11 pointer. Then they set each element corresponding
 * to the fields in the Java object to convert. After use the allocated memory of
 * the PKCS#11 pointer has to be explicitly freed.
 *
 * The functions to convert a PKCS#11 pointer to a Java object create a new Java
 * object first and than they set all fields in the object depending on the values
 * of the type or structure where the PKCS#11 pointer points to.
 */

/*
 * converts a CK_BBOOL pointer to a Java boolean Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpValue - the pointer to the CK_BBOOL value
 * @return - the new Java boolean object with the boolean value
 */
jobject ckBBoolPtrToJBooleanObject(JNIEnv *env, const CK_BBOOL *ckpValue)
{
	jclass jValueObjectClass;
	jmethodID jConstructor;
	jobject jValueObject;
	jboolean jValue;

	jValueObjectClass = (*env)->FindClass(env, "java/lang/Boolean");
	assert(jValueObjectClass != 0);
	jConstructor = (*env)->GetMethodID(env, jValueObjectClass, "<init>", "(Z)V");
	assert(jConstructor != 0);
	jValue = ckBBoolToJBoolean(*ckpValue);
	jValueObject = (*env)->NewObject(env, jValueObjectClass, jConstructor, jValue);
	assert(jValueObject != 0);

	return jValueObject ;
}

/*
 * converts a CK_ULONG pointer to a Java long Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpValue - the pointer to the CK_ULONG value
 * @return - the new Java long object with the long value
 */
jobject ckULongPtrToJLongObject(JNIEnv *env, const CK_ULONG_PTR ckpValue)
{
	jclass jValueObjectClass;
	jmethodID jConstructor;
	jobject jValueObject;
	jlong jValue;

	jValueObjectClass = (*env)->FindClass(env, "java/lang/Long");
	assert(jValueObjectClass != 0);
	jConstructor = (*env)->GetMethodID(env, jValueObjectClass, "<init>", "(J)V");
	assert(jConstructor != 0);
	jValue = ckULongToJLong(*ckpValue);
	jValueObject = (*env)->NewObject(env, jValueObjectClass, jConstructor, jValue);
	assert(jValueObject != 0);

	return jValueObject ;
}

/*
 * converts a pointer to a CK_DATE structure into a Java CK_DATE Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpValue - the pointer to the CK_DATE structure
 * @return - the new Java CK_DATE object
 */
jobject ckDatePtrToJDateObject(JNIEnv *env, const CK_DATE *ckpValue)
{
	jclass jValueObjectClass;
	jobject jValueObject;
	jcharArray jTempCharArray;
	jfieldID fieldID;

	/* load CK_DATE class */
	jValueObjectClass = (*env)->FindClass(env, CLASS_DATE);
	assert(jValueObjectClass != 0);
	/* create new CK_DATE jObject */
	jValueObject = (*env)->AllocObject(env, jValueObjectClass);
	assert(jValueObject != 0);

	/* set year */
	fieldID = (*env)->GetFieldID(env, jValueObjectClass, "year", "[C");
	assert(fieldID != 0);
	jTempCharArray = ckCharArrayToJCharArray(env, (CK_CHAR_PTR)(ckpValue->year), 4);
	(*env)->SetObjectField(env, jValueObject, fieldID, jTempCharArray);

	/* set month */
	fieldID = (*env)->GetFieldID(env, jValueObjectClass, "month", "[C");
	assert(fieldID != 0);
	jTempCharArray = ckCharArrayToJCharArray(env, (CK_CHAR_PTR)(ckpValue->month), 2);
	(*env)->SetObjectField(env, jValueObject, fieldID, jTempCharArray);

	/* set day */
	fieldID = (*env)->GetFieldID(env, jValueObjectClass, "day", "[C");
	assert(fieldID != 0);
	jTempCharArray = ckCharArrayToJCharArray(env, (CK_CHAR_PTR)(ckpValue->day), 2);
	(*env)->SetObjectField(env, jValueObject, fieldID, jTempCharArray);

	return jValueObject ;
}

/*
 * converts a pointer to a CK_VERSION structure into a Java CK_VERSION Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpVersion - the pointer to the CK_VERSION structure
 * @return - the new Java CK_VERSION object
 */
jobject ckVersionPtrToJVersion(JNIEnv *env, const CK_VERSION_PTR ckpVersion)
{
	jclass jVersionClass;
	jobject jVersionObject;
	jfieldID jFieldID;

	/* load CK_VERSION class */
	jVersionClass = (*env)->FindClass(env, CLASS_VERSION);
	assert(jVersionClass != 0);
	/* create new CK_VERSION object */
	jVersionObject = (*env)->AllocObject(env, jVersionClass);
	assert(jVersionObject != 0);
	/* set major */
	jFieldID = (*env)->GetFieldID(env, jVersionClass, "major", "B");
	assert(jFieldID != 0);
	(*env)->SetByteField(env, jVersionObject, jFieldID, (jbyte) (ckpVersion->major));
	/* set minor */
	jFieldID = (*env)->GetFieldID(env, jVersionClass, "minor", "B");
	assert(jFieldID != 0);
	(*env)->SetByteField(env, jVersionObject, jFieldID, (jbyte) (ckpVersion->minor));

	return jVersionObject ;
}

/*
 * converts a pointer to a CK_INFO structure into a Java CK_INFO Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpInfo - the pointer to the CK_INFO structure
 * @return - the new Java CK_INFO object
 */
jobject ckInfoPtrToJInfo(JNIEnv *env, const CK_INFO_PTR ckpInfo)
{
	jclass jInfoClass;
	jobject jInfoObject;
	jcharArray jTempCharArray;
	jfieldID jFieldID;
	jobject jTempVersion;

	/* load CK_INFO class */
	jInfoClass = (*env)->FindClass(env, CLASS_INFO);
	assert(jInfoClass != 0);
	/* create new CK_INFO object */
	jInfoObject = (*env)->AllocObject(env, jInfoClass);
	assert(jInfoObject != 0);

	/* set cryptokiVersion */
	jFieldID = (*env)->GetFieldID(env, jInfoClass, "cryptokiVersion", CLASS_NAME(CLASS_VERSION));
	assert(jFieldID != 0);
	jTempVersion = ckVersionPtrToJVersion(env, &(ckpInfo->cryptokiVersion));
	(*env)->SetObjectField(env, jInfoObject, jFieldID, jTempVersion);

	/* set manufacturerID */
	jFieldID = (*env)->GetFieldID(env, jInfoClass, "manufacturerID", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpInfo->manufacturerID[0]), 32);
	(*env)->SetObjectField(env, jInfoObject, jFieldID, jTempCharArray);

	/* set flags */
	jFieldID = (*env)->GetFieldID(env, jInfoClass, "flags", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jInfoObject, jFieldID, ckULongToJLong(ckpInfo->flags));

	/* set libraryDescription */
	jFieldID = (*env)->GetFieldID(env, jInfoClass, "libraryDescription", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpInfo->libraryDescription[0]) ,32);
	(*env)->SetObjectField(env, jInfoObject, jFieldID, jTempCharArray);

	/* set libraryVersion */
	jFieldID = (*env)->GetFieldID(env, jInfoClass, "libraryVersion", CLASS_NAME(CLASS_VERSION));
	assert(jFieldID != 0);
	jTempVersion = ckVersionPtrToJVersion(env, &(ckpInfo->libraryVersion));
	(*env)->SetObjectField(env, jInfoObject, jFieldID, jTempVersion);

	return jInfoObject ;
}

/*
 * converts a pointer to a CK_SLOT_INFO structure into a Java CK_SLOT_INFO Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpSlotInfo - the pointer to the CK_SLOT_INFO structure
 * @return - the new Java CK_SLOT_INFO object
 */
jobject ckSlotInfoPtrToJSlotInfo(JNIEnv *env, const CK_SLOT_INFO_PTR ckpSlotInfo)
{
	jclass jSlotInfoClass;
	jobject jSlotInfoObject;
	jcharArray jTempCharArray;
	jfieldID jFieldID;
	jobject jTempVersion;

	/* load CK_SLOT_INFO class */
	jSlotInfoClass = (*env)->FindClass(env, CLASS_SLOT_INFO);
	assert(jSlotInfoClass != 0);
	/* create new CK_SLOT_INFO object */
	jSlotInfoObject = (*env)->AllocObject(env, jSlotInfoClass);
	assert(jSlotInfoObject != 0);


	/* set slotDescription */
	jFieldID = (*env)->GetFieldID(env, jSlotInfoClass, "slotDescription", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpSlotInfo->slotDescription[0]) ,64);
	(*env)->SetObjectField(env, jSlotInfoObject, jFieldID, jTempCharArray);

	/* set manufacturerID */
	jFieldID = (*env)->GetFieldID(env, jSlotInfoClass, "manufacturerID", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpSlotInfo->manufacturerID[0]) ,32);
	(*env)->SetObjectField(env, jSlotInfoObject, jFieldID, jTempCharArray);

	/* set flags */
	jFieldID = (*env)->GetFieldID(env, jSlotInfoClass, "flags", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jSlotInfoObject, jFieldID, ckULongToJLong(ckpSlotInfo->flags));

	/* set hardwareVersion */
	jFieldID = (*env)->GetFieldID(env, jSlotInfoClass, "hardwareVersion", CLASS_NAME(CLASS_VERSION));
	assert(jFieldID != 0);
	jTempVersion = ckVersionPtrToJVersion(env, &(ckpSlotInfo->hardwareVersion));
	(*env)->SetObjectField(env, jSlotInfoObject, jFieldID, jTempVersion);

	/* set firmwareVersion */
	jFieldID = (*env)->GetFieldID(env, jSlotInfoClass, "firmwareVersion", CLASS_NAME(CLASS_VERSION));
	assert(jFieldID != 0);
	jTempVersion = ckVersionPtrToJVersion(env, &(ckpSlotInfo->firmwareVersion));
	(*env)->SetObjectField(env, jSlotInfoObject, jFieldID, jTempVersion);

	return jSlotInfoObject ;
}

/*
 * converts a pointer to a CK_TOKEN_INFO structure into a Java CK_TOKEN_INFO Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpTokenInfo - the pointer to the CK_TOKEN_INFO structure
 * @return - the new Java CK_TOKEN_INFO object
 */
jobject ckTokenInfoPtrToJTokenInfo(JNIEnv *env, const CK_TOKEN_INFO_PTR ckpTokenInfo)
{
	jclass jTokenInfoClass;
	jobject jTokenInfoObject;
	jcharArray jTempCharArray;
	jfieldID jFieldID;
	jobject jTempVersion;

	/* load CK_SLOT_INFO class */
	jTokenInfoClass = (*env)->FindClass(env, CLASS_TOKEN_INFO);
	assert(jTokenInfoClass != 0);
	/* create new CK_SLOT_INFO object */
	jTokenInfoObject = (*env)->AllocObject(env, jTokenInfoClass);
	assert(jTokenInfoObject != 0);


	/* set label */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "label", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpTokenInfo->label[0]) ,32);
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempCharArray);

	/* set manufacturerID */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "manufacturerID", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpTokenInfo->manufacturerID[0]) ,32);
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempCharArray);

	/* set model */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "model", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckUTF8CharArrayToJCharArray(env, &(ckpTokenInfo->model[0]) ,16);
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempCharArray);

	/* set serialNumber */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "serialNumber", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckCharArrayToJCharArray(env, &(ckpTokenInfo->serialNumber[0]) ,16);
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempCharArray);

	/* set flags */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "flags", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->flags));

	/* set ulMaxSessionCount */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulMaxSessionCount", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulMaxSessionCount));

	/* set ulSessionCount */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulSessionCount", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulSessionCount));

	/* set ulMaxRwSessionCount */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulMaxRwSessionCount", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulMaxRwSessionCount));

	/* set ulRwSessionCount */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulRwSessionCount", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulRwSessionCount));

	/* set ulMaxPinLen */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulMaxPinLen", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulMaxPinLen));

	/* set ulMinPinLen */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulMinPinLen", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulMinPinLen));

	/* set ulTotalPublicMemory */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulTotalPublicMemory", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulTotalPublicMemory));

	/* set ulFreePublicMemory */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulFreePublicMemory", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulFreePublicMemory));

	/* set ulTotalPrivateMemory */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulTotalPrivateMemory", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulTotalPrivateMemory));

	/* set ulFreePrivateMemory */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "ulFreePrivateMemory", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jTokenInfoObject, jFieldID, ckULongToJLong(ckpTokenInfo->ulFreePrivateMemory));


	/* set hardwareVersion */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "hardwareVersion", CLASS_NAME(CLASS_VERSION));
	assert(jFieldID != 0);
	jTempVersion = ckVersionPtrToJVersion(env, &(ckpTokenInfo->hardwareVersion));
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempVersion);

	/* set firmwareVersion */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "firmwareVersion", CLASS_NAME(CLASS_VERSION));
	assert(jFieldID != 0);
	jTempVersion = ckVersionPtrToJVersion(env, &(ckpTokenInfo->firmwareVersion));
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempVersion);

	/* set utcTime */
	jFieldID = (*env)->GetFieldID(env, jTokenInfoClass, "utcTime", "[C");
	assert(jFieldID != 0);
	jTempCharArray = ckCharArrayToJCharArray(env, &(ckpTokenInfo->utcTime[0]) ,16);
	(*env)->SetObjectField(env, jTokenInfoObject, jFieldID, jTempCharArray);

	return jTokenInfoObject ;
}

/*
 * converts a pointer to a CK_SESSION_INFO structure into a Java CK_SESSION_INFO Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpSessionInfo - the pointer to the CK_SESSION_INFO structure
 * @return - the new Java CK_SESSION_INFO object
 */
jobject ckSessionInfoPtrToJSessionInfo(JNIEnv *env, const CK_SESSION_INFO_PTR ckpSessionInfo)
{
	jclass jSessionInfoClass;
	jobject jSessionInfoObject;
	jfieldID jFieldID;

	/* load CK_SESSION_INFO class */
	jSessionInfoClass = (*env)->FindClass(env, CLASS_SESSION_INFO);
	assert(jSessionInfoClass != 0);
	/* create new CK_SESSION_INFO object */
	jSessionInfoObject = (*env)->AllocObject(env, jSessionInfoClass);
	assert(jSessionInfoObject != 0);

	/* set slotID */
	jFieldID = (*env)->GetFieldID(env, jSessionInfoClass, "slotID", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jSessionInfoObject, jFieldID, ckULongToJLong(ckpSessionInfo->slotID));

	/* set state */
	jFieldID = (*env)->GetFieldID(env, jSessionInfoClass, "state", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jSessionInfoObject, jFieldID, ckULongToJLong(ckpSessionInfo->state));

	/* set flags */
	jFieldID = (*env)->GetFieldID(env, jSessionInfoClass, "flags", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jSessionInfoObject, jFieldID, ckULongToJLong(ckpSessionInfo->flags));

	/* set ulDeviceError */
	jFieldID = (*env)->GetFieldID(env, jSessionInfoClass, "ulDeviceError", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jSessionInfoObject, jFieldID, ckULongToJLong(ckpSessionInfo->ulDeviceError));

	return jSessionInfoObject ;
}

/*
 * converts a pointer to a CK_MECHANISM_INFO structure into a Java CK_MECHANISM_INFO Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpMechanismInfo - the pointer to the CK_MECHANISM_INFO structure
 * @return - the new Java CK_MECHANISM_INFO object
 */
jobject ckMechanismInfoPtrToJMechanismInfo(JNIEnv *env, const CK_MECHANISM_INFO_PTR ckpMechanismInfo)
{
	jclass jMechanismInfoClass;
	jobject jMechanismInfoObject;
	jfieldID jFieldID;

	/* load CK_MECHANISM_INFO class */
	jMechanismInfoClass = (*env)->FindClass(env, CLASS_MECHANISM_INFO);
	assert(jMechanismInfoClass != 0);
	/* create new CK_MECHANISM_INFO object */
	jMechanismInfoObject = (*env)->AllocObject(env, jMechanismInfoClass);
	assert(jMechanismInfoObject != 0);


	/* set ulMinKeySize */
	jFieldID = (*env)->GetFieldID(env, jMechanismInfoClass, "ulMinKeySize", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jMechanismInfoObject, jFieldID, ckULongToJLong(ckpMechanismInfo->ulMinKeySize));

	/* set ulMaxKeySize */
	jFieldID = (*env)->GetFieldID(env, jMechanismInfoClass, "ulMaxKeySize", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jMechanismInfoObject, jFieldID, ckULongToJLong(ckpMechanismInfo->ulMaxKeySize));

	/* set flags */
	jFieldID = (*env)->GetFieldID(env, jMechanismInfoClass, "flags", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jMechanismInfoObject, jFieldID, ckULongToJLong(ckpMechanismInfo->flags));

	return jMechanismInfoObject ;
}

/*
 * converts a pointer to a CK_ATTRIBUTE structure into a Java CK_ATTRIBUTE Object.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpAttribute - the pointer to the CK_ATTRIBUTE structure
 * @return - the new Java CK_ATTRIBUTE object
 */
jobject ckAttributePtrToJAttribute(JNIEnv *env, const CK_ATTRIBUTE_PTR ckpAttribute, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jboolean UseUtf8)
{
	jclass jAttributeClass;
	jobject jAttribute;
	jfieldID jFieldID;
	jobject jPValue = NULL_PTR;

	jAttributeClass = (*env)->FindClass(env, CLASS_ATTRIBUTE);
	assert(jAttributeClass != 0);
	jAttribute = (*env)->AllocObject(env, jAttributeClass);
	assert(jAttribute != 0);

	/* set type */
	jFieldID = (*env)->GetFieldID(env, jAttributeClass, "type", "J");
	assert(jFieldID != 0);
	(*env)->SetLongField(env, jAttribute, jFieldID, ckULongToJLong(ckpAttribute->type));

	/* set pValue */
	jFieldID = (*env)->GetFieldID(env, jAttributeClass, "pValue", "Ljava/lang/Object;");
	assert(jFieldID != 0);

	jPValue = ckAttributeValueToJObject(env, ckpAttribute, obj, jSessionHandle, jObjectHandle, UseUtf8);
	(*env)->SetObjectField(env, jAttribute, jFieldID, jPValue);

	return jAttribute ;
}

/*
 * converts a Java boolean object into a pointer to a CK_BBOOL value. The memory has to be
 * freed after use!
 *
 * @param env - used to call JNI funktions to get the value out of the Java object
 * @param jObject - the "java/lang/Boolean" object to convert
 * @return - the pointer to the new CK_BBOOL value
 */
CK_BBOOL* jBooleanObjectToCKBBoolPtr(JNIEnv *env, jobject jObject)
{
	jclass jObjectClass;
	jmethodID jValueMethod;
	jboolean jValue;
	CK_BBOOL *ckpValue;

	jObjectClass = (*env)->FindClass(env, "java/lang/Boolean");
	assert(jObjectClass != 0);
	jValueMethod = (*env)->GetMethodID(env, jObjectClass, "booleanValue", "()Z");
	assert(jValueMethod != 0);
	jValue = (*env)->CallBooleanMethod(env, jObject, jValueMethod);
	ckpValue = (CK_BBOOL *) malloc(sizeof(CK_BBOOL));
  if (ckpValue == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }
	*ckpValue = jBooleanToCKBBool(jValue);

	return ckpValue ;
}

/*
 * converts a Java byte object into a pointer to a CK_BYTE value. The memory has to be
 * freed after use!
 *
 * @param env - used to call JNI funktions to get the value out of the Java object
 * @param jObject - the "java/lang/Byte" object to convert
 * @return - the pointer to the new CK_BYTE value
 */
CK_BYTE_PTR jByteObjectToCKBytePtr(JNIEnv *env, jobject jObject)
{
	jclass jObjectClass;
	jmethodID jValueMethod;
	jbyte jValue;
	CK_BYTE_PTR ckpValue;

	jObjectClass = (*env)->FindClass(env, "java/lang/Byte");
	assert(jObjectClass != 0);
	jValueMethod = (*env)->GetMethodID(env, jObjectClass, "byteValue", "()B");
	assert(jValueMethod != 0);
	jValue = (*env)->CallByteMethod(env, jObject, jValueMethod);
	ckpValue = (CK_BYTE_PTR) malloc(sizeof(CK_BYTE));
  if (ckpValue == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }
	*ckpValue = jByteToCKByte(jValue);

	return ckpValue ;
}

/*
 * converts a Java integer object into a pointer to a CK_ULONG value. The memory has to be
 * freed after use!
 *
 * @param env - used to call JNI funktions to get the value out of the Java object
 * @param jObject - the "java/lang/Integer" object to convert
 * @return - the pointer to the new CK_ULONG value
 */
CK_ULONG* jIntegerObjectToCKULongPtr(JNIEnv *env, jobject jObject)
{
	jclass jObjectClass;
	jmethodID jValueMethod;
	jint jValue;
	CK_ULONG *ckpValue;

	jObjectClass = (*env)->FindClass(env, "java/lang/Integer");
	assert(jObjectClass != 0);
	jValueMethod = (*env)->GetMethodID(env, jObjectClass, "intValue", "()I");
	assert(jValueMethod != 0);
	jValue = (*env)->CallIntMethod(env, jObject, jValueMethod);
	ckpValue = (CK_ULONG *) malloc(sizeof(CK_ULONG));
  if (ckpValue == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }
	*ckpValue = jLongToCKLong(jValue);

	return ckpValue ;
}

/*
 * converts a Java long object into a pointer to a CK_ULONG value. The memory has to be
 * freed after use!
 *
 * @param env - used to call JNI funktions to get the value out of the Java object
 * @param jObject - the "java/lang/Long" object to convert
 * @return - the pointer to the new CK_ULONG value
 */
CK_ULONG* jLongObjectToCKULongPtr(JNIEnv *env, jobject jObject)
{
	jclass jObjectClass;
	jmethodID jValueMethod;
	jlong jValue;
	CK_ULONG *ckpValue;

	jObjectClass = (*env)->FindClass(env, "java/lang/Long");
	assert(jObjectClass != 0);
	jValueMethod = (*env)->GetMethodID(env, jObjectClass, "longValue", "()J");
	assert(jValueMethod != 0);
	jValue = (*env)->CallLongMethod(env, jObject, jValueMethod);
	ckpValue = (CK_ULONG *) malloc(sizeof(CK_ULONG));
  if (ckpValue == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }
	*ckpValue = jLongToCKULong(jValue);

	return ckpValue ;
}

/*
 * converts a Java char object into a pointer to a CK_CHAR value. The memory has to be
 * freed after use!
 *
 * @param env - used to call JNI funktions to get the value out of the Java object
 * @param jObject - the "java/lang/Char" object to convert
 * @return - the pointer to the new CK_CHAR value
 */
CK_CHAR_PTR jCharObjectToCKCharPtr(JNIEnv *env, jobject jObject)
{
	jclass jObjectClass;
	jmethodID jValueMethod;
	jchar jValue;
	CK_CHAR_PTR ckpValue;

	jObjectClass = (*env)->FindClass(env, "java/lang/Char");
	assert(jObjectClass != 0);
	jValueMethod = (*env)->GetMethodID(env, jObjectClass, "charValue", "()C");
	assert(jValueMethod != 0);
	jValue = (*env)->CallCharMethod(env, jObject, jValueMethod);
	ckpValue = (CK_CHAR_PTR) malloc(sizeof(CK_CHAR));
  if (ckpValue == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }
	*ckpValue = jCharToCKChar(jValue);

	return ckpValue ;
}

/*
 * converts a Java CK_VERSION object into a pointer to a CK_VERSION structure
 *
 * @param env - used to call JNI funktions to get the values out of the Java object
 * @param jVersion - the Java CK_VERSION object to convert
 * @return - the pointer to the new CK_VERSION structure
 */
CK_VERSION_PTR jVersionToCKVersionPtr(JNIEnv *env, jobject jVersion)
{
	CK_VERSION_PTR ckpVersion;
	jclass jVersionClass;
	jfieldID jFieldID;
	jbyte jMajor, jMinor;

	/* allocate memory for CK_VERSION pointer */
	ckpVersion = (CK_VERSION_PTR) malloc(sizeof(CK_VERSION));
  if (ckpVersion == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }

	/* get CK_VERSION class */
	jVersionClass = (*env)->GetObjectClass(env, jVersion);
	assert(jVersionClass != 0);

	/* get Major */
	jFieldID = (*env)->GetFieldID(env, jVersionClass, "major", "B");
	assert(jFieldID != 0);
	jMajor = (*env)->GetByteField(env, jVersion, jFieldID);
	ckpVersion->major = jByteToCKByte(jMajor);

	/* get Minor */
	jFieldID = (*env)->GetFieldID(env, jVersionClass, "minor", "B");
	assert(jFieldID != 0);
	jMinor = (*env)->GetByteField(env, jVersion, jFieldID);
	ckpVersion->minor = jByteToCKByte(jMinor);

	return ckpVersion ;
}


/*
 * converts a Java CK_DATE object into a pointer to a CK_DATE structure
 *
 * @param env - used to call JNI funktions to get the values out of the Java object
 * @param jVersion - the Java CK_DATE object to convert
 * @return - the pointer to the new CK_DATE structure
 */
CK_DATE * jDateObjectPtrToCKDatePtr(JNIEnv *env, jobject jDate)
{
	CK_DATE * ckpDate;
  CK_ULONG ckLength;
	jclass jDateClass;
	jfieldID jFieldID;
	jobject jYear, jMonth, jDay;
  jchar *jTempChars;
  CK_ULONG i;

	/* allocate memory for CK_DATE pointer */
	ckpDate = (CK_DATE *) malloc(sizeof(CK_DATE));
  if (ckpDate == NULL_PTR) { throwOutOfMemoryError(env); return NULL_PTR; }

	/* get CK_DATE class */
	jDateClass = (*env)->FindClass(env, CLASS_DATE);
	assert(jDateClass != 0);

	/* get Year */
	jFieldID = (*env)->GetFieldID(env, jDateClass, "year", "[C");
	assert(jFieldID != 0);
	jYear = (*env)->GetObjectField(env, jDate, jFieldID);

  if (jYear == NULL_PTR) {
    ckpDate->year[0] = 0;
    ckpDate->year[1] = 0;
    ckpDate->year[2] = 0;
    ckpDate->year[3] = 0;
  } else {
  	ckLength = (*env)->GetArrayLength(env, jYear);
	  jTempChars = (jchar*) malloc((ckLength) * sizeof(jchar));
    if (jTempChars == NULL_PTR && ckLength!=0) { free(ckpDate); throwOutOfMemoryError(env); return NULL_PTR; }
  	(*env)->GetCharArrayRegion(env, jYear, 0, ckLength, jTempChars);
    for (i = 0; (i < ckLength) && (i < 4) ; i++) {
      ckpDate->year[i] = jCharToCKChar(jTempChars[i]);
    }
	  free(jTempChars);
  }

	/* get Month */
	jFieldID = (*env)->GetFieldID(env, jDateClass, "month", "[C");
	assert(jFieldID != 0);
	jMonth = (*env)->GetObjectField(env, jDate, jFieldID);

  if (jMonth == NULL_PTR) {
    ckpDate->month[0] = 0;
    ckpDate->month[1] = 0;
  } else {
  	ckLength = (*env)->GetArrayLength(env, jMonth);
	  jTempChars = (jchar*) malloc((ckLength) * sizeof(jchar));
    if (jTempChars == NULL_PTR && ckLength!=0) { free(ckpDate); throwOutOfMemoryError(env); return NULL_PTR; }
  	(*env)->GetCharArrayRegion(env, jMonth, 0, ckLength, jTempChars);
    for (i = 0; (i < ckLength) && (i < 4) ; i++) {
      ckpDate->month[i] = jCharToCKChar(jTempChars[i]);
    }
	  free(jTempChars);
  }

	/* get Day */
	jFieldID = (*env)->GetFieldID(env, jDateClass, "day", "[C");
	assert(jFieldID != 0);
	jDay = (*env)->GetObjectField(env, jDate, jFieldID);

  if (jDay == NULL_PTR) {
    ckpDate->day[0] = 0;
    ckpDate->day[1] = 0;
  } else {
  	ckLength = (*env)->GetArrayLength(env, jDay);
	  jTempChars = (jchar*) malloc((ckLength) * sizeof(jchar));
    if (jTempChars == NULL_PTR && ckLength!=0) { free(ckpDate); throwOutOfMemoryError(env); return NULL_PTR; }
  	(*env)->GetCharArrayRegion(env, jDay, 0, ckLength, jTempChars);
    for (i = 0; (i < ckLength) && (i < 4) ; i++) {
      ckpDate->day[i] = jCharToCKChar(jTempChars[i]);
    }
	  free(jTempChars);
  }

	return ckpDate ;
}


/*
 * converts a Java CK_ATTRIBUTE object into a CK_ATTRIBUTE structure
 *
 * @param env - used to call JNI funktions to get the values out of the Java object
 * @param jAttribute - the Java CK_ATTRIBUTE object to convert
 * @return - the new CK_ATTRIBUTE structure
 */
CK_ATTRIBUTE jAttributeToCKAttribute(JNIEnv *env, jobject jAttribute, jboolean jUseUtf8)
{
	CK_ATTRIBUTE ckAttribute;
	jclass jAttributeClass;
	jfieldID jFieldID;
	jlong jType;
	jobject jPValue;

  TRACE0(tag_call, __FUNCTION__,"entering");

  /* get CK_ATTRIBUTE class */
	TRACE0(tag_debug, __FUNCTION__,"- getting attribute object class");
	jAttributeClass = (*env)->GetObjectClass(env, jAttribute);
	assert(jAttributeClass != 0);

	/* get type */
	TRACE0(tag_debug, __FUNCTION__,"- getting type field");
	jFieldID = (*env)->GetFieldID(env, jAttributeClass, "type", "J");
	assert(jFieldID != 0);
	jType = (*env)->GetLongField(env, jAttribute, jFieldID);
	TRACE1(tag_debug, __FUNCTION__,"  type=0x%llX", jType);

	/* get pValue */
	TRACE0(tag_debug, __FUNCTION__,"- getting pValue field");
	jFieldID = (*env)->GetFieldID(env, jAttributeClass, "pValue", "Ljava/lang/Object;");
	assert(jFieldID != 0);
	jPValue = (*env)->GetObjectField(env, jAttribute, jFieldID);
	TRACE1(tag_debug, __FUNCTION__,"  pValue=%p", jPValue);

	ckAttribute.type = jLongToCKULong(jType);
	TRACE0(tag_debug, __FUNCTION__,"- converting pValue to primitive object");

	if ((ckAttribute.type == 0x40000211) || (ckAttribute.type == 0x40000212)){
		TRACE0(tag_debug, __FUNCTION__,"  CKF_ARRAY_ATTRIBUTE:");
		if (jAttributeArrayToCKAttributeArray(env, jPValue, (CK_ATTRIBUTE_PTR*)&(ckAttribute.pValue), &(ckAttribute.ulValueLen), jUseUtf8)) {
			throwOutOfMemoryError(env); 
		}
		ckAttribute.ulValueLen *= sizeof(CK_ATTRIBUTE);
	} else {
		/* convert the Java pValue object to a CK-type pValue pointer */
		jObjectToPrimitiveCKObjectPtrPtr(env, jPValue, &(ckAttribute.pValue), &(ckAttribute.ulValueLen), jUseUtf8);
	}	

  TRACE0(tag_call, __FUNCTION__,"exiting ");

	return ckAttribute ;
}

/*
 * converts a Java CK_MECHANISM object into a CK_MECHANISM structure
 *
 * @param env - used to call JNI funktions to get the values out of the Java object
 * @param jMechanism - the Java CK_MECHANISM object to convert
 * @return - the new CK_MECHANISM structure
 */
CK_MECHANISM jMechanismToCKMechanism(JNIEnv *env, jobject jMechanism, jboolean jUseUtf8)
{
	CK_MECHANISM ckMechanism;
	jclass jMechanismClass;
	jfieldID fieldID;
	jlong jMechanismType;
	jobject jParameter;

	/* get CK_MECHANISM class */
	jMechanismClass = (*env)->GetObjectClass(env, jMechanism);
	assert(jMechanismClass != 0);

	/* get mechanism */
	fieldID = (*env)->GetFieldID(env, jMechanismClass, "mechanism", "J");
	assert(fieldID != 0);
	jMechanismType = (*env)->GetLongField(env, jMechanism, fieldID);

	/* get pParameter */
	fieldID = (*env)->GetFieldID(env, jMechanismClass, "pParameter", "Ljava/lang/Object;");
	assert(fieldID != 0);
	jParameter = (*env)->GetObjectField(env, jMechanism, fieldID);

	ckMechanism.mechanism = jLongToCKULong(jMechanismType);

	/* convert the specific Java mechanism parameter object to a pointer to a CK-type mechanism
	 * structure
   */
	jMechanismParameterToCKMechanismParameter(env, jParameter, &(ckMechanism.pParameter), &(ckMechanism.ulParameterLen), jUseUtf8);

	return ckMechanism ;
}

void freeCKMechanismParameter(CK_MECHANISM_PTR mechanism) {
  void *value;

  /* free pointers inside parameter structures, see jMechanismParameterToCKMechanismParameter */
  switch (mechanism->mechanism) {
    case CKM_RSA_PKCS_OAEP:
      value = ((CK_RSA_PKCS_OAEP_PARAMS_PTR) mechanism->pParameter)->pSourceData;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_KEA_KEY_DERIVE:
      value = ((CK_KEA_DERIVE_PARAMS_PTR) mechanism->pParameter)->pRandomA;
      if (value != NULL_PTR) free(value);
      value = ((CK_KEA_DERIVE_PARAMS_PTR) mechanism->pParameter)->pRandomB;
      if (value != NULL_PTR) free(value);
      value = ((CK_KEA_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_RC5_CBC:
    case CKM_RC5_CBC_PAD:
      value = ((CK_RC5_CBC_PARAMS_PTR) mechanism->pParameter)->pIv;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_SKIPJACK_PRIVATE_WRAP:
      value = ((CK_SKIPJACK_PRIVATE_WRAP_PTR) mechanism->pParameter)->pPassword;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_PRIVATE_WRAP_PTR) mechanism->pParameter)->pPublicData;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_PRIVATE_WRAP_PTR) mechanism->pParameter)->pRandomA;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_PRIVATE_WRAP_PTR) mechanism->pParameter)->pPrimeP;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_PRIVATE_WRAP_PTR) mechanism->pParameter)->pBaseG;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_PRIVATE_WRAP_PTR) mechanism->pParameter)->pSubprimeQ;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_SKIPJACK_RELAYX:
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pOldWrappedX;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pOldPassword;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pOldPublicData;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pOldRandomA;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pNewPassword;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pNewPublicData;
      if (value != NULL_PTR) free(value);
      value = ((CK_SKIPJACK_RELAYX_PARAMS_PTR) mechanism->pParameter)->pNewRandomA;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_PBE_MD2_DES_CBC:
    case CKM_PBE_MD5_DES_CBC:
    case CKM_PBE_MD5_CAST_CBC:
    case CKM_PBE_MD5_CAST3_CBC:
    case CKM_PBE_MD5_CAST128_CBC:
    /* case CKM_PBE_MD5_CAST5_CBC: */
    case CKM_PBE_SHA1_CAST128_CBC:
    /* case CKM_PBE_SHA1_CAST5_CBC: */
    case CKM_PBE_SHA1_RC4_128:
    case CKM_PBE_SHA1_RC4_40:
    case CKM_PBE_SHA1_DES3_EDE_CBC:
    case CKM_PBE_SHA1_DES2_EDE_CBC:
    case CKM_PBE_SHA1_RC2_128_CBC:
    case CKM_PBE_SHA1_RC2_40_CBC:
    case CKM_PBA_SHA1_WITH_SHA1_HMAC:
      value = ((CK_PBE_PARAMS_PTR) mechanism->pParameter)->pInitVector;
      if (value != NULL_PTR) free(value);
      value = ((CK_PBE_PARAMS_PTR) mechanism->pParameter)->pPassword;
      if (value != NULL_PTR) free(value);
      value = ((CK_PBE_PARAMS_PTR) mechanism->pParameter)->pSalt;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_PKCS5_PBKD2:
      value = ((CK_PKCS5_PBKD2_PARAMS_PTR) mechanism->pParameter)->pSaltSourceData;
      if (value != NULL_PTR) free(value);
      value = ((CK_PKCS5_PBKD2_PARAMS_PTR) mechanism->pParameter)->pPrfData;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_CONCATENATE_BASE_AND_DATA:
    case CKM_XOR_BASE_AND_DATA:
    case CKM_DES_ECB_ENCRYPT_DATA:
    case CKM_DES3_ECB_ENCRYPT_DATA:
    case CKM_AES_ECB_ENCRYPT_DATA:
      value = ((CK_KEY_DERIVATION_STRING_DATA_PTR) mechanism->pParameter)->pData;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_KEY_WRAP_SET_OAEP:
      value = ((CK_KEY_WRAP_SET_OAEP_PARAMS_PTR) mechanism->pParameter)->pX;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_SSL3_MASTER_KEY_DERIVE:
    case CKM_SSL3_MASTER_KEY_DERIVE_DH:
    case CKM_TLS_MASTER_KEY_DERIVE:
    case CKM_TLS_MASTER_KEY_DERIVE_DH:
      value = ((CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR) mechanism->pParameter)->RandomInfo.pClientRandom;
      if (value != NULL_PTR) free(value);
      value = ((CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR) mechanism->pParameter)->RandomInfo.pServerRandom;
      if (value != NULL_PTR) free(value);
      value = ((CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR) mechanism->pParameter)->pVersion;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_SSL3_KEY_AND_MAC_DERIVE:
    case CKM_TLS_KEY_AND_MAC_DERIVE:
      value = ((CK_SSL3_KEY_MAT_PARAMS_PTR) mechanism->pParameter)->RandomInfo.pClientRandom;
      if (value != NULL_PTR) free(value);
      value = ((CK_SSL3_KEY_MAT_PARAMS_PTR) mechanism->pParameter)->RandomInfo.pServerRandom;
      if (value != NULL_PTR) free(value);
      value = ((CK_SSL3_KEY_MAT_PARAMS_PTR) mechanism->pParameter)->pReturnedKeyMaterial->pIVClient;
      if (value != NULL_PTR) free(value);
      value = ((CK_SSL3_KEY_MAT_PARAMS_PTR) mechanism->pParameter)->pReturnedKeyMaterial->pIVServer;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_ECDH1_DERIVE:
    case CKM_ECDH1_COFACTOR_DERIVE:
      value = ((CK_ECDH1_DERIVE_PARAMS_PTR) mechanism->pParameter)->pSharedData;
      if (value != NULL_PTR) free(value);
      value = ((CK_ECDH1_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_ECMQV_DERIVE:
      value = ((CK_ECDH2_DERIVE_PARAMS_PTR) mechanism->pParameter)->pSharedData;
      if (value != NULL_PTR) free(value);
      value = ((CK_ECDH2_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData;
      if (value != NULL_PTR) free(value);
      value = ((CK_ECDH2_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData2;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_X9_42_DH_DERIVE:
      value = ((CK_X9_42_DH1_DERIVE_PARAMS_PTR) mechanism->pParameter)->pOtherInfo;
      if (value != NULL_PTR) free(value);
      value = ((CK_X9_42_DH1_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData;
      if (value != NULL_PTR) free(value);
      break;
    case CKM_X9_42_DH_HYBRID_DERIVE:
    case CKM_X9_42_MQV_DERIVE:
      value = ((CK_X9_42_DH2_DERIVE_PARAMS_PTR) mechanism->pParameter)->pOtherInfo;
      if (value != NULL_PTR) free(value);
      value = ((CK_X9_42_DH2_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData;
      if (value != NULL_PTR) free(value);
      value = ((CK_X9_42_DH2_DERIVE_PARAMS_PTR) mechanism->pParameter)->pPublicData2;
      if (value != NULL_PTR) free(value);
      break;
  }

  /* free parameter structure itself */
  free(mechanism->pParameter);
}

/*
 * the following functions convert Attribute and Mechanism value pointers
 *
 * jobject ckAttributeValueToJObject(JNIEnv *env,
 *                                   const CK_ATTRIBUTE_PTR ckpAttribute);
 *
 * void jObjectToPrimitiveCKObjectPtrPtr(JNIEnv *env,
 *                                       jobject jObject,
 *                                       CK_VOID_PTR *ckpObjectPtr,
 *                                       CK_ULONG *pLength);
 *
 * void jMechanismParameterToCKMechanismParameter(JNIEnv *env,
 *                                                jobject jParam,
 *                                                CK_VOID_PTR *ckpParamPtr,
 *                                                CK_ULONG *ckpLength);
 *
 * These functions are used if a PKCS#11 mechanism or attribute structure gets
 * convertet to a Java attribute or mechanism object or vice versa.
 *
 * ckAttributeValueToJObject converts a PKCS#11 attribute value pointer to a Java
 * object depending on the type of the Attribute. A PKCS#11 attribute value can
 * be a CK_ULONG, CK_BYTE[], CK_CHAR[], big integer, CK_BBOOL, CK_UTF8CHAR[],
 * CK_DATE or CK_FLAGS that gets converted to a corresponding Java object.
 *
 * jObjectToPrimitiveCKObjectPtrPtr is used by jAttributeToCKAttributePtr for
 * converting the Java attribute value to a PKCS#11 attribute value pointer.
 * For now only primitive datatypes and arrays of primitive datatypes can get
 * converted. Otherwise this function throws a PKCS#11Exception with the
 * errorcode CKR_VENDOR_DEFINED.
 *
 * jMechanismParameterToCKMechanismParameter converts a Java mechanism parameter
 * to a PKCS#11 mechanism parameter. First this function determines what mechanism
 * parameter the Java object is, then it allocates the memory for the new PKCS#11
 * structure and calls the corresponding function to convert the Java object to
 * a PKCS#11 mechanism parameter structure.
 */

/*
 * converts the pValue of a CK_ATTRIBUTE structure into a Java Object by checking the type
 * of the attribute.
 *
 * @param env - used to call JNI funktions to create the new Java object
 * @param ckpAttribute - the pointer to the CK_ATTRIBUTE structure that contains the type
 *                       and the pValue to convert
 * @return - the new Java object of the CK-type pValue
 */
jobject ckAttributeValueToJObject(JNIEnv *env, const CK_ATTRIBUTE_PTR ckpAttribute, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jboolean jUseUtf8)
{
	jint jValueLength;
	jobject jValueObject = NULL_PTR;
	CK_BBOOL useUtf8String;

	jValueLength = ckULongToJInt(ckpAttribute->ulValueLen);

	if ((jValueLength <= 0) || (ckpAttribute->pValue == NULL_PTR)) {
		return NULL_PTR ;
	}

	switch(ckpAttribute->type) {
		case CKA_CLASS:
			/* value CK_OBJECT_CLASS, defacto a CK_ULONG */
		case CKA_KEY_TYPE:
			/* value CK_KEY_TYPE, defacto a CK_ULONG */
		case CKA_CERTIFICATE_TYPE:
			/* value CK_CERTIFICATE_TYPE, defacto a CK_ULONG */
		case CKA_HW_FEATURE_TYPE:
			/* value CK_HW_FEATURE_TYPE, defacto a CK_ULONG */
		case CKA_MODULUS_BITS:
		case CKA_VALUE_BITS:
		case CKA_VALUE_LEN:
		case CKA_KEY_GEN_MECHANISM:
		case CKA_PRIME_BITS:
		case CKA_SUB_PRIME_BITS:
		case CKA_CERTIFICATE_CATEGORY:
		case CKA_JAVA_MIDP_SECURITY_DOMAIN:
			/* value CK_ULONG */
			jValueObject = ckULongPtrToJLongObject(env, (CK_ULONG*) ckpAttribute->pValue);
			break;

			/* can be CK_BYTE[],CK_CHAR[] or big integer; defacto always CK_BYTE[] */
		case CKA_VALUE:
		case CKA_OBJECT_ID:
		case CKA_SUBJECT:
		case CKA_ID:
		case CKA_ISSUER:
		case CKA_SERIAL_NUMBER:
		case CKA_OWNER:
		case CKA_AC_ISSUER:
		case CKA_ATTR_TYPES:
		case CKA_ECDSA_PARAMS: 
      /* CKA_EC_PARAMS is the same, these two are equivalent */
		case CKA_EC_POINT:
		case CKA_PRIVATE_EXPONENT:
		case CKA_PRIME_1:
		case CKA_PRIME_2:
		case CKA_EXPONENT_1:
		case CKA_EXPONENT_2:
		case CKA_COEFFICIENT:
		case CKA_CHECK_VALUE:
		case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
		case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
			/* value CK_BYTE[] */
			jValueObject = ckByteArrayToJByteArray(env, (CK_BYTE*) ckpAttribute->pValue, jValueLength);
			break;

		case CKA_RESET_ON_INIT:
		case CKA_HAS_RESET:
		case CKA_TOKEN:
		case CKA_PRIVATE:
		case CKA_MODIFIABLE:
		case CKA_DERIVE:
		case CKA_LOCAL:
		case CKA_ENCRYPT:
		case CKA_VERIFY:
		case CKA_VERIFY_RECOVER:
		case CKA_WRAP:
		case CKA_SENSITIVE:
		case CKA_SECONDARY_AUTH:
		case CKA_DECRYPT:
		case CKA_SIGN:
		case CKA_SIGN_RECOVER:
		case CKA_UNWRAP:
		case CKA_EXTRACTABLE:
		case CKA_ALWAYS_SENSITIVE:
		case CKA_NEVER_EXTRACTABLE:
		case CKA_TRUSTED:
		case CKA_WRAP_WITH_TRUSTED:
		case CKA_ALWAYS_AUTHENTICATE:
			/* value CK_BBOOL */
			jValueObject = ckBBoolPtrToJBooleanObject(env, (CK_BBOOL*) ckpAttribute->pValue);
			break;

		case CKA_LABEL:
		case CKA_APPLICATION:
		case CKA_URL:
			/* value RFC 2279 (UTF-8) string */
			useUtf8String = jBooleanToCKBBool(jUseUtf8);
			if(useUtf8String == TRUE){
				jValueObject = ckUTF8CharArrayToJCharArray(env, (CK_UTF8CHAR*) ckpAttribute->pValue, jValueLength);
			}else{
				jValueObject = ckCharArrayToJCharArray(env, (CK_UTF8CHAR*) ckpAttribute->pValue, jValueLength);
			}
			break;

		case CKA_START_DATE:
		case CKA_END_DATE:
			/* value CK_DATE */
			jValueObject = ckDatePtrToJDateObject(env, (CK_DATE*) ckpAttribute->pValue);
			break;

		case CKA_MODULUS:
		case CKA_PUBLIC_EXPONENT:
		case CKA_PRIME:
		case CKA_SUBPRIME:
		case CKA_BASE:
			/* value big integer, i.e. CK_BYTE[] */
			jValueObject = ckByteArrayToJByteArray(env, (CK_BYTE*) ckpAttribute->pValue, jValueLength);
			break;

		case CKA_AUTH_PIN_FLAGS:
			jValueObject = ckULongPtrToJLongObject(env, (CK_ULONG*) ckpAttribute->pValue);
			/* value FLAGS, defacto a CK_ULONG */
			break;

		case CKA_ALLOWED_MECHANISMS:
			jValueLength = jValueLength / sizeof(CK_MECHANISM_TYPE);
			jValueObject = ckULongArrayToJLongArray(env, (CK_ULONG*) ckpAttribute->pValue, jValueLength);
			break;

		case CKA_WRAP_TEMPLATE:
		case CKA_UNWRAP_TEMPLATE:
			jValueObject = ckAttributeArrayToJAttributeArray(env, (CK_ATTRIBUTE*) ckpAttribute->pValue, jValueLength, obj, jSessionHandle, jObjectHandle, jUseUtf8);
			break;

		case CKA_VENDOR_DEFINED:
			/* we make a CK_BYTE[] out of this */
			jValueObject = ckByteArrayToJByteArray(env, (CK_BYTE*) ckpAttribute->pValue, jValueLength);
			break;

		default:
			/* we make a CK_BYTE[] out of this */
			jValueObject = ckByteArrayToJByteArray(env, (CK_BYTE*) ckpAttribute->pValue, jValueLength);
			break;
	}

	return jValueObject ;
}

/*
 * converts a Java object into a pointer to CK-type or a CK-structure with the length in Bytes.
 * The memory of *ckpObjectPtr to be freed after use! This function is only used by
 * jAttributeToCKAttribute by now.
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jObject - the Java object to convert
 * @param ckpObjectPtr - the reference of the new pointer to the new CK-value or CK-structure
 * @param ckpLength - the reference of the length in bytes of the new CK-value or CK-structure
 */
void jObjectToPrimitiveCKObjectPtrPtr(JNIEnv *env, jobject jObject, CK_VOID_PTR *ckpObjectPtr, CK_ULONG *ckpLength, jboolean jUseUtf8)
{
	jclass jBooleanClass     = (*env)->FindClass(env, "java/lang/Boolean");
	jclass jByteClass        = (*env)->FindClass(env, "java/lang/Byte");
	jclass jCharacterClass   = (*env)->FindClass(env, "java/lang/Character");
	jclass jClassClass = (*env)->FindClass(env, "java/lang/Class");
	/* jclass jShortClass       = (*env)->FindClass(env, "java/lang/Short"); */
	jclass jIntegerClass     = (*env)->FindClass(env, "java/lang/Integer");
	jclass jLongClass        = (*env)->FindClass(env, "java/lang/Long");
	/* jclass jFloatClass       = (*env)->FindClass(env, "java/lang/Float"); */
	/* jclass jDoubleClass      = (*env)->FindClass(env, "java/lang/Double"); */
	jclass jDateClass      = (*env)->FindClass(env, CLASS_DATE);
	jclass jStringClass      = (*env)->FindClass(env, "java/lang/String");
	jclass jStringBufferClass      = (*env)->FindClass(env, "java/lang/StringBuffer");
	jclass jBooleanArrayClass = (*env)->FindClass(env, "[Z");
	jclass jByteArrayClass    = (*env)->FindClass(env, "[B");
	jclass jCharArrayClass    = (*env)->FindClass(env, "[C");
	/* jclass jShortArrayClass   = (*env)->FindClass(env, "[S"); */
	jclass jIntArrayClass     = (*env)->FindClass(env, "[I");
	jclass jLongArrayClass    = (*env)->FindClass(env, "[J");
	/* jclass jFloatArrayClass   = (*env)->FindClass(env, "[F"); */
	/* jclass jDoubleArrayClass  = (*env)->FindClass(env, "[D"); */
	jclass jObjectClass = (*env)->FindClass(env, "java/lang/Object");
  /*  jclass jObjectArrayClass = (*env)->FindClass(env, "[java/lang/Object"); */
  /* ATTENTION: jObjectArrayClass is always NULL_PTR !! */
  /* CK_ULONG ckArrayLength; */
	/* CK_VOID_PTR *ckpElementObject; */
	/* CK_ULONG ckElementLength; */
	/* CK_ULONG i; */
  CK_VOID_PTR ckpVoid = *ckpObjectPtr;
	jmethodID jMethod;
  jobject jClassObject;
  jstring jClassNameString;
  jstring jExceptionMessagePrefix;
  jobject jExceptionMessageStringBuffer;
  jstring jExceptionMessage;
  CK_BBOOL ckUseUtf8;
/*#if DEBUG
  char buffer[buffer_size];
  int i = 0;
  for(i; i < buffer_size; i++)
  	buffer[i] = '\0';
#endif*/

  TRACE0(tag_call, __FUNCTION__,"entering");

	if (jObject == NULL_PTR) {
		*ckpObjectPtr = NULL_PTR;
		*ckpLength = 0;
		TRACE0(tag_debug, __FUNCTION__, "- converted NULL_PTR value");
	} else if ((*env)->IsInstanceOf(env, jObject, jLongClass)) {
		*ckpObjectPtr = jLongObjectToCKULongPtr(env, jObject);
		*ckpLength = sizeof(CK_ULONG);
		TRACE1(tag_debug, __FUNCTION__,"- converted long value %lX", *((CK_ULONG *) *ckpObjectPtr));
	} else if ((*env)->IsInstanceOf(env, jObject, jBooleanClass)) {
		*ckpObjectPtr = jBooleanObjectToCKBBoolPtr(env, jObject);
		*ckpLength = sizeof(CK_BBOOL);
		TRACE0(tag_debug, __FUNCTION__,(*((CK_BBOOL *) *ckpObjectPtr) == TRUE) ? "- converted boolean value TRUE>" : "- converted boolean value FALSE>");
	} else if ((*env)->IsInstanceOf(env, jObject, jByteArrayClass)) {
		jByteArrayToCKByteArray(env, jObject, (CK_BYTE_PTR*)ckpObjectPtr, ckpLength);
/*#if DEBUG
		byteArrayToHexString((char *)(*ckpObjectPtr), *ckpLength, buffer, buffer_size);
		TRACE1(tag_debug, __FUNCTION__, "- converted byte array: %s", buffer);
#endif*/
	} else if ((*env)->IsInstanceOf(env, jObject, jCharArrayClass)) {
		ckUseUtf8 = jBooleanToCKBBool(jUseUtf8);
		if(ckUseUtf8 == TRUE){
			jCharArrayToCKUTF8CharArray(env, jObject, (CK_UTF8CHAR_PTR*)ckpObjectPtr, ckpLength);
		}else{
			jCharArrayToCKCharArray(env, jObject, (CK_UTF8CHAR_PTR*)ckpObjectPtr, ckpLength);
		}
		TRACE0(tag_debug, __FUNCTION__, "- converted char array");
	} else if ((*env)->IsInstanceOf(env, jObject, jByteClass)) {
		*ckpObjectPtr = jByteObjectToCKBytePtr(env, jObject);
		*ckpLength = sizeof(CK_BYTE);
		TRACE1(tag_debug, __FUNCTION__,"- converted byte value %X", *((CK_BYTE *) *ckpObjectPtr));
	} else if ((*env)->IsInstanceOf(env, jObject, jDateClass)) {
		*ckpObjectPtr = jDateObjectPtrToCKDatePtr(env, jObject);
		*ckpLength = sizeof(CK_DATE);
		TRACE3(tag_debug, __FUNCTION__,"- converted date value %.4s-%.2s-%.2s", (*((CK_DATE *) *ckpObjectPtr)).year,
                                                    (*((CK_DATE *) *ckpObjectPtr)).month,
                                                    (*((CK_DATE *) *ckpObjectPtr)).day);
	} else if ((*env)->IsInstanceOf(env, jObject, jCharacterClass)) {
		*ckpObjectPtr = jCharObjectToCKCharPtr(env, jObject);
		*ckpLength = sizeof(CK_UTF8CHAR);
		TRACE1(tag_debug, __FUNCTION__,"- converted char value %c", *((CK_CHAR *) *ckpObjectPtr));
	} else if ((*env)->IsInstanceOf(env, jObject, jIntegerClass)) {
		*ckpObjectPtr = jIntegerObjectToCKULongPtr(env, jObject);
		*ckpLength = sizeof(CK_ULONG);
		TRACE1(tag_debug, __FUNCTION__,"- converted integer value %lX", *((CK_ULONG *) *ckpObjectPtr));
	} else if ((*env)->IsInstanceOf(env, jObject, jBooleanArrayClass)) {
		jBooleanArrayToCKBBoolArray(env, jObject, (CK_BBOOL**)ckpObjectPtr, ckpLength);
		TRACE0(tag_debug, __FUNCTION__, "- converted boolean array");
	} else if ((*env)->IsInstanceOf(env, jObject, jIntArrayClass)) {
		jLongArrayToCKULongArray(env, jObject, (CK_ULONG_PTR*)ckpObjectPtr, ckpLength);
		TRACE0(tag_debug, __FUNCTION__, "- converted int array");
} else if ((*env)->IsInstanceOf(env, jObject, jLongArrayClass)) {
		jLongArrayToCKULongArray(env, jObject, (CK_ULONG_PTR*)ckpObjectPtr, ckpLength);
		*ckpLength = *ckpLength * sizeof(CK_MECHANISM_TYPE);
		TRACE0(tag_debug, __FUNCTION__, "- converted long array");
} else if ((*env)->IsInstanceOf(env, jObject, jStringClass)) {
		jStringToCKUTF8CharArray(env, jObject, (CK_UTF8CHAR_PTR*)ckpObjectPtr, ckpLength);
		TRACE0(tag_debug, __FUNCTION__, "- converted string");

    /* a Java object array is not used by CK_ATTRIBUTE by now... */
/*	} else if ((*env)->IsInstanceOf(env, jObject, jObjectArrayClass)) {
		ckArrayLength = (*env)->GetArrayLength(env, (jarray) jObject);
		ckpObjectPtr = (CK_VOID_PTR_PTR) malloc(sizeof(CK_VOID_PTR) * ckArrayLength);
    if (ckpObjectPtr == NULL_PTR && ckArrayLength!=0) { *ckpObjectPtr = NULL_PTR; throwOutOfMemoryError(env); return NULL_PTR; }
		*ckpLength = 0;
		for (i = 0; i < ckArrayLength; i++) {
			jObjectToPrimitiveCKObjectPtrPtr(env, (*env)->GetObjectArrayElement(env, (jarray) jObject, i),
									   ckpElementObject, &ckElementLength);
			(*ckpObjectPtr)[i] = *ckpElementObject;
			*ckpLength += ckElementLength;
		}
*/
	} else {
		TRACE0(tag_error, __FUNCTION__, "- Java object of this class cannot be converted to native PKCS#11 type");

		/* type of jObject unknown, throw PKCS11RuntimeException */
	  jMethod = (*env)->GetMethodID(env, jObjectClass, "getClass", "()Ljava/lang/Class;");
	  assert(jMethod != 0);
    jClassObject = (*env)->CallObjectMethod(env, jObject, jMethod);
	  assert(jClassObject != 0);
	  jMethod = (*env)->GetMethodID(env, jClassClass, "getName", "()Ljava/lang/String;");
	  assert(jMethod != 0);
    jClassNameString = (jstring)
        (*env)->CallObjectMethod(env, jClassObject, jMethod);
	  assert(jClassNameString != 0);
    jExceptionMessagePrefix = (*env)->NewStringUTF(env, "Java object of this class cannot be converted to native PKCS#11 type: ");
	  jMethod = (*env)->GetMethodID(env, jStringBufferClass, "<init>", "(Ljava/lang/String;)V");
	  assert(jMethod != 0);
    jExceptionMessageStringBuffer = (*env)->NewObject(env, jStringBufferClass, jMethod, jExceptionMessagePrefix);
	  assert(jClassNameString != 0);
	  jMethod = (*env)->GetMethodID(env, jStringBufferClass, "append", "(Ljava/lang/String;)Ljava/lang/StringBuffer;");
	  assert(jMethod != 0);
    jExceptionMessage = (jstring)
         (*env)->CallObjectMethod(env, jExceptionMessageStringBuffer, jMethod, jClassNameString);
	  assert(jExceptionMessage != 0);

	  throwPKCS11RuntimeException(env, jExceptionMessage);

		*ckpObjectPtr = NULL_PTR;
		*ckpLength = 0;
	}

  TRACE0(tag_call, __FUNCTION__,"exiting ");
}

/*
 * the following functions convert a Java mechanism parameter object to a PKCS#11
 * mechanism parameter structure
 *
 * CK_<Param>_PARAMS j<Param>ParamToCK<Param>Param(JNIEnv *env,
 *                                                 jobject jParam);
 *
 * These functions get a Java object, that must be the right Java mechanism
 * object and they return the new PKCS#11 mechanism parameter structure.
 * Every field of the Java object is retrieved, gets converted to a corresponding
 * PKCS#11 type and is set in the new PKCS#11 structure.
 */

/*
 * converts the given Java mechanism parameter to a CK mechanism parameter structure
 * and store the length in bytes in the length variable.
 * The memory of *ckpParamPtr has to be freed after use!
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java mechanism parameter object to convert
 * @param ckpParamPtr - the reference of the new pointer to the new CK mechanism parameter
 *                      structure
 * @param ckpLength - the reference of the length in bytes of the new CK mechanism parameter
 *                    structure
 */
void jMechanismParameterToCKMechanismParameter(JNIEnv *env, jobject jParam, CK_VOID_PTR *ckpParamPtr, CK_ULONG *ckpLength, jboolean jUseUtf8)
{
	/* get all Java mechanism parameter classes */
	jclass jByteArrayClass    = (*env)->FindClass(env, "[B");
	jclass jLongClass        = (*env)->FindClass(env, "java/lang/Long");
	jclass jVersionClass    = (*env)->FindClass(env, CLASS_VERSION);
	jclass jRsaPkcsOaepParamsClass = (*env)->FindClass(env, CLASS_RSA_PKCS_OAEP_PARAMS);
	jclass jKeaDeriveParamsClass = (*env)->FindClass(env, CLASS_KEA_DERIVE_PARAMS);
  jclass jRc2CbcParamsClass = (*env)->FindClass(env, CLASS_RC2_CBC_PARAMS);
	jclass jRc2MacGeneralParamsClass = (*env)->FindClass(env, CLASS_RC2_MAC_GENERAL_PARAMS);
	jclass jRc5ParamsClass = (*env)->FindClass(env, CLASS_RC5_PARAMS);
  jclass jRc5CbcParamsClass = (*env)->FindClass(env, CLASS_RC5_CBC_PARAMS);
	jclass jRc5MacGeneralParamsClass = (*env)->FindClass(env, CLASS_RC5_MAC_GENERAL_PARAMS);
	jclass jSkipjackPrivateWrapParamsClass = (*env)->FindClass(env, CLASS_SKIPJACK_PRIVATE_WRAP_PARAMS);
	jclass jSkipjackRelayxParamsClass = (*env)->FindClass(env, CLASS_SKIPJACK_RELAYX_PARAMS);
	jclass jPbeParamsClass = (*env)->FindClass(env, CLASS_PBE_PARAMS);
	jclass jPkcs5Pbkd2ParamsClass = (*env)->FindClass(env, CLASS_PKCS5_PBKD2_PARAMS);
	jclass jKeyWrapSetOaepParamsClass = (*env)->FindClass(env, CLASS_KEY_WRAP_SET_OAEP_PARAMS);
  jclass jKeyDerivationStringDataClass = (*env)->FindClass(env, CLASS_KEY_DERIVATION_STRING_DATA);
	jclass jSsl3MasterKeyDeriveParamsClass = (*env)->FindClass(env, CLASS_SSL3_MASTER_KEY_DERIVE_PARAMS);
	jclass jSsl3KeyMatParamsClass = (*env)->FindClass(env, CLASS_SSL3_KEY_MAT_PARAMS);

	jclass jRsaPkcsPssParamsClass = (*env)->FindClass(env, CLASS_RSA_PKCS_PSS_PARAMS);
	jclass jEcdh1DeriveParamsClass = (*env)->FindClass(env, CLASS_ECDH1_DERIVE_PARAMS);
	jclass jEcdh2DeriveParamsClass = (*env)->FindClass(env, CLASS_ECDH2_DERIVE_PARAMS);
	jclass jX942Dh1DeriveParamsClass = (*env)->FindClass(env, CLASS_X9_42_DH1_DERIVE_PARAMS);
	jclass jX942Dh2DeriveParamsClass = (*env)->FindClass(env, CLASS_X9_42_DH2_DERIVE_PARAMS);
	jclass jDesCbcEncryptDataParamsClass = (*env)->FindClass(env, CLASS_DES_CBC_ENCRYPT_DATA_PARAMS);
	jclass jAesCbcEncryptDataParamsClass = (*env)->FindClass(env, CLASS_AES_CBC_ENCRYPT_DATA_PARAMS);

  /* first check the most common cases */
	if (jParam == NULL_PTR) {
		*ckpParamPtr = NULL_PTR;
		*ckpLength = 0;
  } else if ((*env)->IsInstanceOf(env, jParam, jByteArrayClass)) {
    jByteArrayToCKByteArray(env, jParam, (CK_BYTE_PTR *)ckpParamPtr, ckpLength);
  } else if ((*env)->IsInstanceOf(env, jParam, jLongClass)) {
		*ckpParamPtr = jLongObjectToCKULongPtr(env, jParam);
		*ckpLength = sizeof(CK_ULONG);
  } else if ((*env)->IsInstanceOf(env, jParam, jVersionClass)) {
		/*
		 * CK_VERSION used by CKM_SSL3_PRE_MASTER_KEY_GEN
		 */

		CK_VERSION_PTR ckpParam;

		/* convert jParameter to CKParameter */
		ckpParam = jVersionToCKVersionPtr(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_VERSION);
		*ckpParamPtr = ckpParam;

  } else if ((*env)->IsInstanceOf(env, jParam, jRsaPkcsOaepParamsClass)) {
		/*
		 * CK_RSA_PKCS_OAEP_PARAMS
		 */

		CK_RSA_PKCS_OAEP_PARAMS_PTR ckpParam;

		ckpParam = (CK_RSA_PKCS_OAEP_PARAMS_PTR) malloc(sizeof(CK_RSA_PKCS_OAEP_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRsaPkcsOaepParamToCKRsaPkcsOaepParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jKeaDeriveParamsClass)) {
		/*
		 * CK_KEA_DERIVE_PARAMS
		 */

		CK_KEA_DERIVE_PARAMS_PTR ckpParam;

		ckpParam = (CK_KEA_DERIVE_PARAMS_PTR) malloc(sizeof(CK_KEA_DERIVE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jKeaDeriveParamToCKKeaDeriveParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_KEA_DERIVE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jRc2CbcParamsClass)) {
		/*
		 * CK_RC2_CBC_PARAMS
		 */

		CK_RC2_CBC_PARAMS_PTR ckpParam;

		ckpParam = (CK_RC2_CBC_PARAMS_PTR) malloc(sizeof(CK_RC2_CBC_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRc2CbcParamToCKRc2CbcParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RC2_CBC_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jRc2MacGeneralParamsClass)) {
		/*
		 * CK_RC2_MAC_GENERAL_PARAMS
		 */

		CK_RC2_MAC_GENERAL_PARAMS_PTR ckpParam;

		ckpParam = (CK_RC2_MAC_GENERAL_PARAMS_PTR) malloc(sizeof(CK_RC2_MAC_GENERAL_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRc2MacGeneralParamToCKRc2MacGeneralParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RC2_MAC_GENERAL_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jRc5ParamsClass)) {
		/*
		 * CK_RC5_PARAMS
		 */

		CK_RC5_PARAMS_PTR ckpParam;

		ckpParam = (CK_RC5_PARAMS_PTR) malloc(sizeof(CK_RC5_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRc5ParamToCKRc5Param(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RC5_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jRc5CbcParamsClass)) {
		/*
		 * CK_RC5_CBC_PARAMS
		 */

		CK_RC5_CBC_PARAMS_PTR ckpParam;

		ckpParam = (CK_RC5_CBC_PARAMS_PTR) malloc(sizeof(CK_RC5_CBC_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRc5CbcParamToCKRc5CbcParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RC5_CBC_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jRc5MacGeneralParamsClass)) {
		/*
		 * CK_RC5_MAC_GENERAL_PARAMS
		 */

		CK_RC5_MAC_GENERAL_PARAMS_PTR ckpParam;

		ckpParam = (CK_RC5_MAC_GENERAL_PARAMS_PTR) malloc(sizeof(CK_RC5_MAC_GENERAL_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRc5MacGeneralParamToCKRc5MacGeneralParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RC5_MAC_GENERAL_PARAMS);

		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jSkipjackPrivateWrapParamsClass)) {
		/*
		 * CK_SKIPJACK_PRIVATE_WRAP_PARAMS
		 */

		CK_SKIPJACK_PRIVATE_WRAP_PTR ckpParam;

		ckpParam = (CK_SKIPJACK_PRIVATE_WRAP_PTR) malloc(sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jSkipjackPrivateWrapParamToCKSkipjackPrivateWrapParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_SKIPJACK_PRIVATE_WRAP_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jSkipjackRelayxParamsClass)) {
		/*
		 * CK_SKIPJACK_RELAYX_PARAMS
		 */

		CK_SKIPJACK_RELAYX_PARAMS_PTR ckpParam;

		ckpParam = (CK_SKIPJACK_RELAYX_PARAMS_PTR) malloc(sizeof(CK_SKIPJACK_RELAYX_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jSkipjackRelayxParamToCKSkipjackRelayxParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_SKIPJACK_RELAYX_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jPbeParamsClass)) {
		/*
		 * CK_PBE_PARAMS
		 */

		CK_PBE_PARAMS_PTR ckpParam;

		ckpParam = (CK_PBE_PARAMS_PTR) malloc(sizeof(CK_PBE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jPbeParamToCKPbeParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_PBE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jPkcs5Pbkd2ParamsClass)) {
		/*
		 * CK_PKCS5_PBKD2_PARAMS
		 */

		CK_PKCS5_PBKD2_PARAMS_PTR ckpParam;

		ckpParam = (CK_PKCS5_PBKD2_PARAMS_PTR) malloc(sizeof(CK_PKCS5_PBKD2_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jPkcs5Pbkd2ParamToCKPkcs5Pbkd2Param(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_PKCS5_PBKD2_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jKeyDerivationStringDataClass)) {
		/*
		 * CK_KEY_DERIVATION_STRING_DATA
		 */

		CK_KEY_DERIVATION_STRING_DATA_PTR ckpParam;

		ckpParam = (CK_KEY_DERIVATION_STRING_DATA_PTR) malloc(sizeof(CK_KEY_DERIVATION_STRING_DATA));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jKeyDerivationStringDataToCKKeyDerivationStringData(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_KEY_DERIVATION_STRING_DATA);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jKeyWrapSetOaepParamsClass)) {
		/*
		 * CK_KEY_WRAP_SET_OAEP_PARAMS
		 */

		CK_KEY_WRAP_SET_OAEP_PARAMS_PTR ckpParam;

		ckpParam = (CK_KEY_WRAP_SET_OAEP_PARAMS_PTR) malloc(sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jKeyWrapSetOaepParamToCKKeyWrapSetOaepParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_KEY_WRAP_SET_OAEP_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jSsl3MasterKeyDeriveParamsClass)) {
		/*
		 * CK_SSL3_MASTER_KEY_DERIVE_PARAMS
		 */

		CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR ckpParam;

		ckpParam = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR) malloc(sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jSsl3MasterKeyDeriveParamToCKSsl3MasterKeyDeriveParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jSsl3KeyMatParamsClass)) {
		/*
		 * CK_SSL3_KEY_MAT_PARAMS
		 */

		CK_SSL3_KEY_MAT_PARAMS_PTR ckpParam;

		ckpParam = (CK_SSL3_KEY_MAT_PARAMS_PTR) malloc(sizeof(CK_SSL3_KEY_MAT_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jSsl3KeyMatParamToCKSsl3KeyMatParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_SSL3_KEY_MAT_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jRsaPkcsPssParamsClass)) {
		/*
		 * CK_RSA_PKCS_PSS_PARAMS
		 */

		CK_RSA_PKCS_PSS_PARAMS_PTR ckpParam;

		ckpParam = (CK_RSA_PKCS_PSS_PARAMS_PTR) malloc(sizeof(CK_RSA_PKCS_PSS_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jRsaPkcsPssParamToCKRsaPkcsPssParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_RSA_PKCS_PSS_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jEcdh1DeriveParamsClass)) {
		/*
		 * CK_ECDH1_DERIVE_PARAMS
		 */

		CK_ECDH1_DERIVE_PARAMS_PTR ckpParam;

		ckpParam = (CK_ECDH1_DERIVE_PARAMS_PTR) malloc(sizeof(CK_ECDH1_DERIVE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jEcdh1DeriveParamToCKEcdh1DeriveParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_ECDH1_DERIVE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jEcdh2DeriveParamsClass)) {
		/*
		 * CK_ECDH2_DERIVE_PARAMS
		 */

		CK_ECDH2_DERIVE_PARAMS_PTR ckpParam;

		ckpParam = (CK_ECDH2_DERIVE_PARAMS_PTR) malloc(sizeof(CK_ECDH2_DERIVE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jEcdh2DeriveParamToCKEcdh2DeriveParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_ECDH2_DERIVE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jX942Dh1DeriveParamsClass)) {
		/*
		 * CK_X9_42_DH1_DERIVE_PARAMS
		 */

		CK_X9_42_DH1_DERIVE_PARAMS_PTR ckpParam;

		ckpParam = (CK_X9_42_DH1_DERIVE_PARAMS_PTR) malloc(sizeof(CK_X9_42_DH1_DERIVE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jX942Dh1DeriveParamToCKX942Dh1DeriveParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_X9_42_DH1_DERIVE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jX942Dh2DeriveParamsClass)) {
		/*
		 * CK_X9_42_DH2_DERIVE_PARAMS
		 */

		CK_X9_42_DH2_DERIVE_PARAMS_PTR ckpParam;

		ckpParam = (CK_X9_42_DH2_DERIVE_PARAMS_PTR) malloc(sizeof(CK_X9_42_DH2_DERIVE_PARAMS));
    if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jX942Dh2DeriveParamToCKX942Dh2DeriveParam(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_X9_42_DH2_DERIVE_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jDesCbcEncryptDataParamsClass)) {
		/*
		* CK_DES_CBC_ENCRYPT_DATA_PARAMS
		*/

		CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR ckpParam;

		ckpParam = (CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR) malloc(sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS));
		if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jDesCbcEncryptDataParamToCKDesCbcEncryptData(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_DES_CBC_ENCRYPT_DATA_PARAMS);
		*ckpParamPtr = ckpParam;

	} else if ((*env)->IsInstanceOf(env, jParam, jAesCbcEncryptDataParamsClass)) {
		/*
		* CK_AES_CBC_ENCRYPT_DATA_PARAMS
		*/

		CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR ckpParam;

		ckpParam = (CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR) malloc(sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS));
		if (ckpParam == NULL_PTR) { *ckpParamPtr = NULL_PTR; throwOutOfMemoryError(env); return; }

		/* convert jParameter to CKParameter */
		*ckpParam = jAesCbcEncryptDataParamToCKAesCbcEncryptData(env, jParam);

		/* get length and pointer of parameter */
		*ckpLength = sizeof(CK_AES_CBC_ENCRYPT_DATA_PARAMS);
		*ckpParamPtr = ckpParam;

	} else {
    /* if everything faild up to here */
    /* try if the parameter is a primitive Java type */
    jObjectToPrimitiveCKObjectPtrPtr(env, jParam, ckpParamPtr, ckpLength, jUseUtf8);
		/* *ckpParamPtr = jObjectToCKVoidPtr(jParam); */
		/* *ckpLength = 1; */
	}
}


/* the mechanism parameter convertion functions: */

/*
 * converts the Java CK_DES_CBC_ENCRYPT_DATA_PARAMS object to a CK_DES_CBC_ENCRYPT_DATA_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_DES_CBC_ENCRYPT_DATA_PARAMS object to convert
 * @return - the new CK_DES_CBC_ENCRYPT_DATA_PARAMS structure
 */
CK_DES_CBC_ENCRYPT_DATA_PARAMS jDesCbcEncryptDataParamToCKDesCbcEncryptData(JNIEnv *env, jobject jParam)
{
	jclass jDesCbcEncryptDataParamsClass = (*env)->FindClass(env, CLASS_DES_CBC_ENCRYPT_DATA_PARAMS);
	CK_DES_CBC_ENCRYPT_DATA_PARAMS ckParam;
	jfieldID fieldID;
	jobject jObject;
	CK_BYTE_PTR ckpByte;
	CK_LONG ivLength;

	/* get iv */
	fieldID = (*env)->GetFieldID(env, jDesCbcEncryptDataParamsClass, "iv", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &ckpByte, &ivLength);
	memcpy(ckParam.iv, ckpByte, ivLength);
	free(ckpByte);

	/* get pData and length */
	fieldID = (*env)->GetFieldID(env, jDesCbcEncryptDataParamsClass, "pData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &ckpByte, &(ckParam.length));
	ckParam.pData = (CK_VOID_PTR) ckpByte;

	return ckParam ;
}


/*
 * converts the Java CK_AES_CBC_ENCRYPT_DATA_PARAMS object to a CK_AES_CBC_ENCRYPT_DATA_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_AES_CBC_ENCRYPT_DATA_PARAMS object to convert
 * @return - the new CK_AES_CBC_ENCRYPT_DATA_PARAMS structure
 */
CK_AES_CBC_ENCRYPT_DATA_PARAMS jAesCbcEncryptDataParamToCKAesCbcEncryptData(JNIEnv *env, jobject jParam)
{
	jclass jAesCbcEncryptDataParamsClass = (*env)->FindClass(env, CLASS_AES_CBC_ENCRYPT_DATA_PARAMS);
	CK_AES_CBC_ENCRYPT_DATA_PARAMS ckParam;
	jfieldID fieldID;
	jobject jObject;
	CK_BYTE_PTR ckpByte;
	CK_LONG ivLength;

	/* get iv */
	fieldID = (*env)->GetFieldID(env, jAesCbcEncryptDataParamsClass, "iv", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &ckpByte, &ivLength);
	memcpy(ckParam.iv, ckpByte, ivLength);
	free(ckpByte);

	/* get pData and length */
	fieldID = (*env)->GetFieldID(env, jAesCbcEncryptDataParamsClass, "pData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &ckpByte, &(ckParam.length));
	ckParam.pData = (CK_VOID_PTR) ckpByte;

	return ckParam ;
}

/*
 * converts the Java CK_RSA_PKCS_OAEP_PARAMS object to a CK_RSA_PKCS_OAEP_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RSA_PKCS_OAEP_PARAMS object to convert
 * @return - the new CK_RSA_PKCS_OAEP_PARAMS structure
 */
CK_RSA_PKCS_OAEP_PARAMS jRsaPkcsOaepParamToCKRsaPkcsOaepParam(JNIEnv *env, jobject jParam)
{
	jclass jRsaPkcsOaepParamsClass = (*env)->FindClass(env, CLASS_RSA_PKCS_OAEP_PARAMS);
	CK_RSA_PKCS_OAEP_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;
	CK_BYTE_PTR ckpByte;

	/* get hashAlg */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsOaepParamsClass, "hashAlg", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.hashAlg = jLongToCKULong(jLong);

	/* get mgf */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsOaepParamsClass, "mgf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.mgf = jLongToCKULong(jLong);

	/* get source */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsOaepParamsClass, "source", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.source = jLongToCKULong(jLong);

	/* get sourceData and sourceDataLength */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsOaepParamsClass, "pSourceData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &ckpByte, &(ckParam.ulSourceDataLen));
	ckParam.pSourceData = (CK_VOID_PTR) ckpByte;

	return ckParam ;
}

/*
 * converts the Java CK_KEA_DERIVE_PARAMS object to a CK_KEA_DERIVE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_KEA_DERIVE_PARAMS object to convert
 * @return - the new CK_KEA_DERIVE_PARAMS structure
 */
CK_KEA_DERIVE_PARAMS jKeaDeriveParamToCKKeaDeriveParam(JNIEnv *env, jobject jParam)
{
	jclass jKeaDeriveParamsClass = (*env)->FindClass(env, CLASS_KEA_DERIVE_PARAMS);
	CK_KEA_DERIVE_PARAMS ckParam;
	jfieldID fieldID;
	jboolean jBoolean;
	jobject jObject;
	CK_ULONG ckTemp;

	/* get isSender */
	fieldID = (*env)->GetFieldID(env, jKeaDeriveParamsClass, "isSender", "Z");
	assert(fieldID != 0);
	jBoolean = (*env)->GetBooleanField(env, jParam, fieldID);
	ckParam.isSender = jBooleanToCKBBool(jBoolean);

	/* get pRandomA and ulRandomLength */
	fieldID = (*env)->GetFieldID(env, jKeaDeriveParamsClass, "pRandomA", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pRandomA), &ckTemp);

	/* get pRandomB and ulRandomLength */
	fieldID = (*env)->GetFieldID(env, jKeaDeriveParamsClass, "pRandomB", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pRandomB), &(ckParam.ulRandomLen));
	/* pRandomA and pRandomB must have the same length */
	assert(ckTemp == ckParam.ulRandomLen);		/* pRandomALength == pRandomBLength */

	/* get pPublicData and ulPublicDataLength */
	fieldID = (*env)->GetFieldID(env, jKeaDeriveParamsClass, "pPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData), &(ckParam.ulPublicDataLen));

	return ckParam ;
}

/*
 * converts the Java CK_RC2_CBC_PARAMS object to a CK_RC2_CBC_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RC2_CBC_PARAMS object to convert
 * @return - the new CK_RC2_CBC_PARAMS structure
 */
CK_RC2_CBC_PARAMS jRc2CbcParamToCKRc2CbcParam(JNIEnv *env, jobject jParam)
{
	jclass jRc2CbcParamsClass = (*env)->FindClass(env, CLASS_RC2_CBC_PARAMS);
	CK_RC2_CBC_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jbyte* jpTemp;
	CK_ULONG i;
  jbyteArray jArray;
  jint jLength;
  CK_ULONG ckLength;

	/* get ulEffectiveBits */
	fieldID = (*env)->GetFieldID(env, jRc2CbcParamsClass, "ulEffectiveBits", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulEffectiveBits = jLongToCKULong(jLong);

	/* get iv[8] */
	fieldID = (*env)->GetFieldID(env, jRc2CbcParamsClass, "iv", "[B");
	assert(fieldID != 0);
	jArray = (jbyteArray) (*env)->GetObjectField(env, jParam, fieldID);
	assert(jArray != NULL_PTR);

	jLength = (*env)->GetArrayLength(env, jArray);
  assert(jLength == 8); /*  iv is a BYTE[8] array */
  ckLength = jIntToCKULong(jLength);
	jpTemp = (jbyte *) malloc(ckLength * sizeof(jbyte));
  if (jpTemp == NULL_PTR && ckLength!=0) { throwOutOfMemoryError(env); return ckParam; }
	(*env)->GetByteArrayRegion(env, jArray, 0, ckLength, jpTemp);
	for (i=0; i < ckLength; i++) {
		(ckParam.iv)[i] = jByteToCKByte(jpTemp[i]);
	}
	free(jpTemp);

	return ckParam ;
}

/*
 * converts the Java CK_RC2_MAC_GENERAL_PARAMS object to a CK_RC2_MAC_GENERAL_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RC2_MAC_GENERAL_PARAMS object to convert
 * @return - the new CK_RC2_MAC_GENERAL_PARAMS structure
 */
CK_RC2_MAC_GENERAL_PARAMS jRc2MacGeneralParamToCKRc2MacGeneralParam(JNIEnv *env, jobject jParam)
{
	jclass jRc2MacGeneralParamsClass = (*env)->FindClass(env, CLASS_RC2_MAC_GENERAL_PARAMS);
	CK_RC2_MAC_GENERAL_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;

	/* get ulEffectiveBits */
	fieldID = (*env)->GetFieldID(env, jRc2MacGeneralParamsClass, "ulEffectiveBits", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulEffectiveBits = jLongToCKULong(jLong);

	/* get ulMacLength */
	fieldID = (*env)->GetFieldID(env, jRc2MacGeneralParamsClass, "ulMacLength", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulMacLength = jLongToCKULong(jLong);

	return ckParam ;
}

/*
 * converts the Java CK_RC5_PARAMS object to a CK_RC5_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RC5_PARAMS object to convert
 * @return - the new CK_RC5_PARAMS structure
 */
CK_RC5_PARAMS jRc5ParamToCKRc5Param(JNIEnv *env, jobject jParam)
{
	jclass jRc5ParamsClass = (*env)->FindClass(env, CLASS_RC5_PARAMS);
	CK_RC5_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;

	/* get ulWordsize */
	fieldID = (*env)->GetFieldID(env, jRc5ParamsClass, "ulWordsize", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulWordsize = jLongToCKULong(jLong);

	/* get ulRounds */
	fieldID = (*env)->GetFieldID(env, jRc5ParamsClass, "ulRounds", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulRounds = jLongToCKULong(jLong);

	return ckParam ;
}

/*
 * converts the Java CK_RC5_CBC_PARAMS object to a CK_RC5_CBC_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RC5_CBC_PARAMS object to convert
 * @return - the new CK_RC5_CBC_PARAMS structure
 */
CK_RC5_CBC_PARAMS jRc5CbcParamToCKRc5CbcParam(JNIEnv *env, jobject jParam)
{
	jclass jRc5CbcParamsClass = (*env)->FindClass(env, CLASS_RC5_CBC_PARAMS);
	CK_RC5_CBC_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;

	/* get ulWordsize */
	fieldID = (*env)->GetFieldID(env, jRc5CbcParamsClass, "ulWordsize", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulWordsize = jLongToCKULong(jLong);

	/* get ulRounds */
	fieldID = (*env)->GetFieldID(env, jRc5CbcParamsClass, "ulRounds", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulRounds = jLongToCKULong(jLong);

	/* get pIv and ulIvLen */
	fieldID = (*env)->GetFieldID(env, jRc5CbcParamsClass, "pIv", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pIv), &(ckParam.ulIvLen));

	return ckParam ;
}

/*
 * converts the Java CK_RC5_MAC_GENERAL_PARAMS object to a CK_RC5_MAC_GENERAL_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RC5_MAC_GENERAL_PARAMS object to convert
 * @return - the new CK_RC5_MAC_GENERAL_PARAMS structure
 */
CK_RC5_MAC_GENERAL_PARAMS jRc5MacGeneralParamToCKRc5MacGeneralParam(JNIEnv *env, jobject jParam)
{
	jclass jRc5MacGeneralParamsClass = (*env)->FindClass(env, CLASS_RC5_MAC_GENERAL_PARAMS);
	CK_RC5_MAC_GENERAL_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;

	/* get ulWordsize */
	fieldID = (*env)->GetFieldID(env, jRc5MacGeneralParamsClass, "ulWordsize", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulWordsize = jLongToCKULong(jLong);

	/* get ulRounds */
	fieldID = (*env)->GetFieldID(env, jRc5MacGeneralParamsClass, "ulRounds", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulRounds = jLongToCKULong(jLong);

	/* get ulMacLength */
	fieldID = (*env)->GetFieldID(env, jRc5MacGeneralParamsClass, "ulMacLength", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulMacLength = jLongToCKULong(jLong);

	return ckParam ;
}

/*
 * converts the Java CK_SKIPJACK_PRIVATE_WRAP_PARAMS object to a CK_SKIPJACK_PRIVATE_WRAP_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_SKIPJACK_PRIVATE_WRAP_PARAMS object to convert
 * @return - the new CK_SKIPJACK_PRIVATE_WRAP_PARAMS structure
 */
CK_SKIPJACK_PRIVATE_WRAP_PARAMS jSkipjackPrivateWrapParamToCKSkipjackPrivateWrapParam(JNIEnv *env, jobject jParam)
{
	jclass jSkipjackPrivateWrapParamsClass = (*env)->FindClass(env, CLASS_SKIPJACK_PRIVATE_WRAP_PARAMS);
	CK_SKIPJACK_PRIVATE_WRAP_PARAMS ckParam;
	jfieldID fieldID;
	jobject jObject;
	CK_ULONG ckTemp;

	/* get pPassword and ulPasswordLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackPrivateWrapParamsClass, "pPassword", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPassword), &(ckParam.ulPasswordLen));

	/* get pPublicData and ulPublicDataLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackPrivateWrapParamsClass, "pPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData), &(ckParam.ulPublicDataLen));

	/* get pRandomA and ulRandomLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackPrivateWrapParamsClass, "pRandomA", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pRandomA), &(ckParam.ulRandomLen));

	/* get pPrimeP and ulPandGLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackPrivateWrapParamsClass, "pPrimeP", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPrimeP), &ckTemp);

	/* get pBaseG and ulPAndGLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackPrivateWrapParamsClass, "pBaseG", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pBaseG), &(ckParam.ulPAndGLen));
	/* pPrimeP and pBaseG must have the same length */
	assert(ckTemp == ckParam.ulPAndGLen);

	/* get pSubprimeQ and ulQLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackPrivateWrapParamsClass, "pSubprimeQ", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pSubprimeQ), &(ckParam.ulQLen));

	return ckParam ;
}

/*
 * converts the Java CK_SKIPJACK_RELAYX_PARAMS object to a CK_SKIPJACK_RELAYX_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_SKIPJACK_RELAYX_PARAMS object to convert
 * @return - the new CK_SKIPJACK_RELAYX_PARAMS structure
 */
CK_SKIPJACK_RELAYX_PARAMS jSkipjackRelayxParamToCKSkipjackRelayxParam(JNIEnv *env, jobject jParam)
{
	jclass jSkipjackRelayxParamsClass = (*env)->FindClass(env, CLASS_SKIPJACK_RELAYX_PARAMS);
	CK_SKIPJACK_RELAYX_PARAMS ckParam;
	jfieldID fieldID;
	jobject jObject;

	/* get pOldWrappedX and ulOldWrappedXLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pOldWrappedX", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pOldWrappedX), &(ckParam.ulOldWrappedXLen));

	/* get pOldPassword and ulOldPasswordLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pOldPassword", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pOldPassword), &(ckParam.ulOldPasswordLen));

	/* get pOldPublicData and ulOldPublicDataLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pOldPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pOldPublicData), &(ckParam.ulOldPublicDataLen));

	/* get pOldRandomA and ulOldRandomLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pOldRandomA", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pOldRandomA), &(ckParam.ulOldRandomLen));

	/* get pNewPassword and ulNewPasswordLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pNewPassword", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pNewPassword), &(ckParam.ulNewPasswordLen));

	/* get pNewPublicData and ulNewPublicDataLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pNewPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pNewPublicData), &(ckParam.ulNewPublicDataLen));

	/* get pNewRandomA and ulNewRandomLength */
	fieldID = (*env)->GetFieldID(env, jSkipjackRelayxParamsClass, "pNewRandomA", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pNewRandomA), &(ckParam.ulNewRandomLen));

	return ckParam ; 
}

/*
 * converts the Java CK_PBE_PARAMS object to a CK_PBE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_PBE_PARAMS object to convert
 * @return - the new CK_PBE_PARAMS structure
 */
CK_PBE_PARAMS jPbeParamToCKPbeParam(JNIEnv *env, jobject jParam)
{
	jclass jPbeParamsClass = (*env)->FindClass(env, CLASS_PBE_PARAMS);
	CK_PBE_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;
	CK_ULONG ckTemp;

	/* get pInitVector */
	fieldID = (*env)->GetFieldID(env, jPbeParamsClass, "pInitVector", "[C");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jCharArrayToCKCharArray(env, jObject, &(ckParam.pInitVector), &ckTemp);

	/* get pPassword and ulPasswordLength */
	fieldID = (*env)->GetFieldID(env, jPbeParamsClass, "pPassword", "[C");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jCharArrayToCKCharArray(env, jObject, &(ckParam.pPassword), &(ckParam.ulPasswordLen));

	/* get pSalt and ulSaltLength */
	fieldID = (*env)->GetFieldID(env, jPbeParamsClass, "pSalt", "[C");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jCharArrayToCKCharArray(env, jObject, &(ckParam.pSalt), &(ckParam.ulSaltLen));

	/* get ulIteration */
	fieldID = (*env)->GetFieldID(env, jPbeParamsClass, "ulIteration", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulIteration = jLongToCKULong(jLong);

	return ckParam ;
}

/*
 * Copy back the initialization vector from the native structure to the
 * Java object. This is only used for CKM_PBE_* mechanisms and their
 * CK_PBE_PARAMS parameters.
 *
 */
void copyBackPBEInitializationVector(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism)
{
	jclass jMechanismClass= (*env)->FindClass(env, CLASS_MECHANISM);
	jclass jPbeParamsClass = (*env)->FindClass(env, CLASS_PBE_PARAMS);
	CK_PBE_PARAMS *ckParam;
	jfieldID fieldID;
  CK_MECHANISM_TYPE ckMechanismType;
	jlong jMechanismType;
	jobject jParameter;
	jobject jInitVector;
	jint jInitVectorLength;
  CK_CHAR_PTR initVector;
	int i;
	jchar* jInitVectorChars;

	/* get mechanism */
	fieldID = (*env)->GetFieldID(env, jMechanismClass, "mechanism", "J");
	assert(fieldID != 0);
	jMechanismType = (*env)->GetLongField(env, jMechanism, fieldID);
  ckMechanismType = jLongToCKULong(jMechanismType);
  if (ckMechanismType != ckMechanism->mechanism) {
    /* we do not have maching types, this should not occur */
    return;
  }

  ckParam = (CK_PBE_PARAMS *) ckMechanism->pParameter;
  if (ckParam != NULL_PTR) {
    initVector = ckParam->pInitVector;
    if (initVector != NULL_PTR) {
	    /* get pParameter */
	    fieldID = (*env)->GetFieldID(env, jMechanismClass, "pParameter", "Ljava/lang/Object;");
	    assert(fieldID != 0);
	    jParameter = (*env)->GetObjectField(env, jMechanism, fieldID);
	    fieldID = (*env)->GetFieldID(env, jPbeParamsClass, "pInitVektor", "[C");
	    assert(fieldID != 0);
      jInitVector = (*env)->GetObjectField(env, jParameter, fieldID);

      if (jInitVector != NULL_PTR) {
        jInitVectorLength = (*env)->GetArrayLength(env, jInitVector);
        jInitVectorChars = (*env)->GetCharArrayElements(env, jInitVector, NULL_PTR);
        /* copy the chars to the Java buffer */
	      for (i=0; i < jInitVectorLength; i++) {
		      jInitVectorChars[i] = ckCharToJChar(initVector[i]);
	      }
        /* copy back the Java buffer to the object */
	      (*env)->ReleaseCharArrayElements(env, jInitVector, jInitVectorChars, 0);
      }
    }
  }
}

/*
 * converts the Java CK_PKCS5_PBKD2_PARAMS object to a CK_PKCS5_PBKD2_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_PKCS5_PBKD2_PARAMS object to convert
 * @return - the new CK_PKCS5_PBKD2_PARAMS structure
 */
CK_PKCS5_PBKD2_PARAMS jPkcs5Pbkd2ParamToCKPkcs5Pbkd2Param(JNIEnv *env, jobject jParam)
{
	jclass jPkcs5Pbkd2ParamsClass = (*env)->FindClass(env, CLASS_PKCS5_PBKD2_PARAMS);
	CK_PKCS5_PBKD2_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;

	/* get saltSource */
	fieldID = (*env)->GetFieldID(env, jPkcs5Pbkd2ParamsClass, "saltSource", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.saltSource = jLongToCKULong(jLong);

	/* get pSaltSourceData */
	fieldID = (*env)->GetFieldID(env, jPkcs5Pbkd2ParamsClass, "pSaltSourceData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, (CK_BYTE_PTR *) &(ckParam.pSaltSourceData), &(ckParam.ulSaltSourceDataLen));

	/* get iterations */
	fieldID = (*env)->GetFieldID(env, jPkcs5Pbkd2ParamsClass, "iterations", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.iterations = jLongToCKULong(jLong);

	/* get prf */
	fieldID = (*env)->GetFieldID(env, jPkcs5Pbkd2ParamsClass, "prf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.prf = jLongToCKULong(jLong);

	/* get pPrfData and ulPrfDataLength in byte */
	fieldID = (*env)->GetFieldID(env, jPkcs5Pbkd2ParamsClass, "pPrfData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, (CK_BYTE_PTR *) &(ckParam.pPrfData), &(ckParam.ulPrfDataLen));

	return ckParam ;
}

/*
 * converts the Java CK_KEY_WRAP_SET_OAEP_PARAMS object to a CK_KEY_WRAP_SET_OAEP_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_KEY_WRAP_SET_OAEP_PARAMS object to convert
 * @return - the new CK_KEY_WRAP_SET_OAEP_PARAMS structure
 */
CK_KEY_WRAP_SET_OAEP_PARAMS jKeyWrapSetOaepParamToCKKeyWrapSetOaepParam(JNIEnv *env, jobject jParam)
{
	jclass jKeyWrapSetOaepParamsClass = (*env)->FindClass(env, CLASS_KEY_WRAP_SET_OAEP_PARAMS);
	CK_KEY_WRAP_SET_OAEP_PARAMS ckParam;
	jfieldID fieldID;
	jbyte jByte;
	jobject jObject;

	/* get bBC */
	fieldID = (*env)->GetFieldID(env, jKeyWrapSetOaepParamsClass, "bBC", "B");
	assert(fieldID != 0);
	jByte = (*env)->GetByteField(env, jParam, fieldID);
	ckParam.bBC = jByteToCKByte(jByte);

	/* get pX and ulXLength */
	fieldID = (*env)->GetFieldID(env, jKeyWrapSetOaepParamsClass, "pX", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pX), &(ckParam.ulXLen));

	return ckParam ;
}

/*
 * Copy back the unwrapped key info from the native structure to the
 * Java object. This is only used for the CK_KEY_WRAP_SET_OAEP_PARAMS 
 * mechanism when used for unwrapping a key.
 *
 */
void copyBackSetUnwrappedKey(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism)
{
	jclass jMechanismClass= (*env)->FindClass(env, CLASS_MECHANISM);
	jclass jSetParamsClass = (*env)->FindClass(env, CLASS_KEY_WRAP_SET_OAEP_PARAMS);
	CK_KEY_WRAP_SET_OAEP_PARAMS *ckKeyWrapSetOaepParams;
	jfieldID fieldID;
  CK_MECHANISM_TYPE ckMechanismType;
	jlong jMechanismType;
  CK_BYTE_PTR x;
	jobject jParameter;
	jobject jx;
	jint jxLength;
	jbyte* jxBytes;
	int i;

	/* get mechanism */
	fieldID = (*env)->GetFieldID(env, jMechanismClass, "mechanism", "J");
	assert(fieldID != 0);
	jMechanismType = (*env)->GetLongField(env, jMechanism, fieldID);
  ckMechanismType = jLongToCKULong(jMechanismType);
  if (ckMechanismType != ckMechanism->mechanism) {
    /* we do not have maching types, this should not occur */
    return;
  }

  ckKeyWrapSetOaepParams = (CK_KEY_WRAP_SET_OAEP_PARAMS *) ckMechanism->pParameter;
  if (ckKeyWrapSetOaepParams != NULL_PTR) {
    x = ckKeyWrapSetOaepParams->pX;
    if (x != NULL_PTR) {
	    /* get pParameter */
	    fieldID = (*env)->GetFieldID(env, jMechanismClass, "pParameter", "Ljava/lang/Object;");
	    assert(fieldID != 0);
	    jParameter = (*env)->GetObjectField(env, jMechanism, fieldID);

      /* copy back the bBC */
	    fieldID = (*env)->GetFieldID(env, jSetParamsClass, "bBC", "B");
	    assert(fieldID != 0);
      (*env)->SetByteField(env, jParameter, fieldID, ckKeyWrapSetOaepParams->bBC);

      /* copy back the pX */
	    fieldID = (*env)->GetFieldID(env, jSetParamsClass, "pX", "[B");
	    assert(fieldID != 0);
      jx = (*env)->GetObjectField(env, jParameter, fieldID);

      if (jx != NULL_PTR) {
        jxLength = (*env)->GetArrayLength(env, jx);
        jxBytes = (*env)->GetByteArrayElements(env, jx, NULL_PTR);
        /* copy the bytes to the Java buffer */
	      for (i=0; i < jxLength; i++) {
		      jxBytes[i] = ckByteToJByte(x[i]);
	      }
        /* copy back the Java buffer to the object */
	      (*env)->ReleaseByteArrayElements(env, jx, jxBytes, 0);
      }
    }
  }
}


/*
 * Copy back the client version information from the native 
 * structure to the Java object. This is only used for the 
 * CKM_SSL3_MASTER_KEY_DERIVE mechanism when used for deriving a key.
 *
 */
void copyBackClientVersion(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism)
{
	jclass jMechanismClass= (*env)->FindClass(env, CLASS_MECHANISM);
	jclass jSSL3MasterKeyDeriveParamsClass = (*env)->FindClass(env, CLASS_SSL3_MASTER_KEY_DERIVE_PARAMS);
	jclass jVersionClass = (*env)->FindClass(env, CLASS_VERSION);
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS *ckSSL3MasterKeyDeriveParams;
	CK_VERSION *ckVersion;
	jfieldID fieldID;
  CK_MECHANISM_TYPE ckMechanismType;
	jlong jMechanismType;
	jobject jSSL3MasterKeyDeriveParams;
	jobject jVersion;

	/* get mechanism */
	fieldID = (*env)->GetFieldID(env, jMechanismClass, "mechanism", "J");
	assert(fieldID != 0);
	jMechanismType = (*env)->GetLongField(env, jMechanism, fieldID);
  ckMechanismType = jLongToCKULong(jMechanismType);
  if (ckMechanismType != ckMechanism->mechanism) {
    /* we do not have maching types, this should not occur */
    return;
  }

  /* get the native CK_SSL3_MASTER_KEY_DERIVE_PARAMS */
  ckSSL3MasterKeyDeriveParams = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS *) ckMechanism->pParameter;
  if (ckSSL3MasterKeyDeriveParams != NULL_PTR) {
    /* get the native CK_VERSION */
    ckVersion = ckSSL3MasterKeyDeriveParams->pVersion;
    if (ckVersion != NULL_PTR) {
      /* get the Java CK_SSL3_MASTER_KEY_DERIVE_PARAMS (pParameter) */
	    fieldID = (*env)->GetFieldID(env, jMechanismClass, "pParameter", "Ljava/lang/Object;");
	    assert(fieldID != 0);
	    jSSL3MasterKeyDeriveParams = (*env)->GetObjectField(env, jMechanism, fieldID);

      /* get the Java CK_VERSION */
	    fieldID = (*env)->GetFieldID(env, jSSL3MasterKeyDeriveParamsClass, "pVersion", "L"CLASS_VERSION";");
	    assert(fieldID != 0);
      jVersion = (*env)->GetObjectField(env, jSSL3MasterKeyDeriveParams, fieldID);

      /* now copy back the version from the native structure to the Java structure */

      /* copy back the major version */
 	    fieldID = (*env)->GetFieldID(env, jVersionClass, "major", "B");
	    assert(fieldID != 0);
      (*env)->SetByteField(env, jVersion, fieldID, ckByteToJByte(ckVersion->major));

      /* copy back the minor version */
	    fieldID = (*env)->GetFieldID(env, jVersionClass, "minor", "B");
	    assert(fieldID != 0);
      (*env)->SetByteField(env, jVersion, fieldID, ckByteToJByte(ckVersion->minor));
    }
  }
}


/*
 * Copy back the derived keys and initialization vectors from the native 
 * structure to the Java object. This is only used for the 
 * CKM_SSL3_KEY_AND_MAC_DERIVE mechanism when used for deriving a key.
 *
 */
void copyBackSSLKeyMatParams(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism)
{
	jclass jMechanismClass= (*env)->FindClass(env, CLASS_MECHANISM);
	jclass jSSL3KeyMatParamsClass = (*env)->FindClass(env, CLASS_SSL3_KEY_MAT_PARAMS);
	jclass jSSL3KeyMatOutClass = (*env)->FindClass(env, CLASS_SSL3_KEY_MAT_OUT);
	CK_SSL3_KEY_MAT_PARAMS *ckSSL3KeyMatParam;
	CK_SSL3_KEY_MAT_OUT *ckSSL3KeyMatOut;
	jfieldID fieldID;
  CK_MECHANISM_TYPE ckMechanismType;
	jlong jMechanismType;
  CK_BYTE_PTR iv;
	jobject jSSL3KeyMatParam;
	jobject jSSL3KeyMatOut;
	jobject jIV;
	jint jLength;
	jbyte* jBytes;
	int i;

	/* get mechanism */
	fieldID = (*env)->GetFieldID(env, jMechanismClass, "mechanism", "J");
	assert(fieldID != 0);
	jMechanismType = (*env)->GetLongField(env, jMechanism, fieldID);
  ckMechanismType = jLongToCKULong(jMechanismType);
  if (ckMechanismType != ckMechanism->mechanism) {
    /* we do not have maching types, this should not occur */
    return;
  }

  /* get the native CK_SSL3_KEY_MAT_PARAMS */
  ckSSL3KeyMatParam = (CK_SSL3_KEY_MAT_PARAMS *) ckMechanism->pParameter;
  if (ckSSL3KeyMatParam != NULL_PTR) {
    /* get the native CK_SSL3_KEY_MAT_OUT */
    ckSSL3KeyMatOut = ckSSL3KeyMatParam->pReturnedKeyMaterial;
    if (ckSSL3KeyMatOut != NULL_PTR) {
      /* get the Java CK_SSL3_KEY_MAT_PARAMS (pParameter) */
	    fieldID = (*env)->GetFieldID(env, jMechanismClass, "pParameter", "Ljava/lang/Object;");
	    assert(fieldID != 0);
	    jSSL3KeyMatParam = (*env)->GetObjectField(env, jMechanism, fieldID);

      /* get the Java CK_SSL3_KEY_MAT_OUT */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatParamsClass, "pReturnedKeyMaterial", "L"CLASS_SSL3_KEY_MAT_OUT";");
	    assert(fieldID != 0);
      jSSL3KeyMatOut = (*env)->GetObjectField(env, jSSL3KeyMatParam, fieldID);

      /* now copy back all the key handles and the initialization vectors */
      /* copy back client MAC secret handle */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatOutClass, "hClientMacSecret", "J");
	    assert(fieldID != 0);
      (*env)->SetLongField(env, jSSL3KeyMatOut, fieldID, ckULongToJLong(ckSSL3KeyMatOut->hClientMacSecret));

      /* copy back server MAC secret handle */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatOutClass, "hServerMacSecret", "J");
	    assert(fieldID != 0);
      (*env)->SetLongField(env, jSSL3KeyMatOut, fieldID, ckULongToJLong(ckSSL3KeyMatOut->hServerMacSecret));

      /* copy back client secret key handle */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatOutClass, "hClientKey", "J");
	    assert(fieldID != 0);
      (*env)->SetLongField(env, jSSL3KeyMatOut, fieldID, ckULongToJLong(ckSSL3KeyMatOut->hClientKey));

      /* copy back server secret key handle */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatOutClass, "hServerKey", "J");
	    assert(fieldID != 0);
      (*env)->SetLongField(env, jSSL3KeyMatOut, fieldID, ckULongToJLong(ckSSL3KeyMatOut->hServerKey));

      /* copy back the client IV */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatOutClass, "pIVClient", "[B");
	    assert(fieldID != 0);
      jIV = (*env)->GetObjectField(env, jSSL3KeyMatOut, fieldID);
      iv = ckSSL3KeyMatOut->pIVClient;

      if (jIV != NULL_PTR) {
        jLength = (*env)->GetArrayLength(env, jIV);
        jBytes = (*env)->GetByteArrayElements(env, jIV, NULL_PTR);
        /* copy the bytes to the Java buffer */
	      for (i=0; i < jLength; i++) {
		      jBytes[i] = ckByteToJByte(iv[i]);
	      }
        /* copy back the Java buffer to the object */
	      (*env)->ReleaseByteArrayElements(env, jIV, jBytes, 0);
      }

      /* copy back the server IV */
	    fieldID = (*env)->GetFieldID(env, jSSL3KeyMatOutClass, "pIVServer", "[B");
	    assert(fieldID != 0);
      jIV = (*env)->GetObjectField(env, jSSL3KeyMatOut, fieldID);
      iv = ckSSL3KeyMatOut->pIVServer;

      if (jIV != NULL_PTR) {
        jLength = (*env)->GetArrayLength(env, jIV);
        jBytes = (*env)->GetByteArrayElements(env, jIV, NULL_PTR);
        /* copy the bytes to the Java buffer */
	      for (i=0; i < jLength; i++) {
		      jBytes[i] = ckByteToJByte(iv[i]);
	      }
        /* copy back the Java buffer to the object */
	      (*env)->ReleaseByteArrayElements(env, jIV, jBytes, 0);
      }
    }
  }
}


/*
 * converts the Java CK_SSL3_MASTER_KEY_DERIVE_PARAMS object to a
 * CK_SSL3_MASTER_KEY_DERIVE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_SSL3_MASTER_KEY_DERIVE_PARAMS object to convert
 * @return - the new CK_SSL3_MASTER_KEY_DERIVE_PARAMS structure
 */
CK_SSL3_MASTER_KEY_DERIVE_PARAMS jSsl3MasterKeyDeriveParamToCKSsl3MasterKeyDeriveParam(JNIEnv *env, jobject jParam)
{
	jclass jSsl3MasterKeyDeriveParamsClass = (*env)->FindClass(env, CLASS_SSL3_MASTER_KEY_DERIVE_PARAMS);
	CK_SSL3_MASTER_KEY_DERIVE_PARAMS ckParam;
	jfieldID fieldID;
	jobject jObject;
	jclass jSsl3RandomDataClass;
	jobject jRandomInfo;

	/* get RandomInfo */
	jSsl3RandomDataClass = (*env)->FindClass(env, CLASS_SSL3_RANDOM_DATA);
	fieldID = (*env)->GetFieldID(env, jSsl3MasterKeyDeriveParamsClass, "RandomInfo", CLASS_NAME(CLASS_SSL3_RANDOM_DATA));
	assert(fieldID != 0);
	jRandomInfo = (*env)->GetObjectField(env, jParam, fieldID);

	/* get pClientRandom and ulClientRandomLength out of RandomInfo */
	fieldID = (*env)->GetFieldID(env, jSsl3RandomDataClass, "pClientRandom", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jRandomInfo, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.RandomInfo.pClientRandom), &(ckParam.RandomInfo.ulClientRandomLen));

	/* get pServerRandom and ulServerRandomLength out of RandomInfo */
	fieldID = (*env)->GetFieldID(env, jSsl3RandomDataClass, "pServerRandom", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jRandomInfo, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.RandomInfo.pServerRandom), &(ckParam.RandomInfo.ulServerRandomLen));

	/* get pVersion */
	fieldID = (*env)->GetFieldID(env, jSsl3MasterKeyDeriveParamsClass, "pVersion", CLASS_NAME(CLASS_VERSION));
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	ckParam.pVersion = jVersionToCKVersionPtr(env, jObject);

	return ckParam ;
}

/*
 * converts the Java CK_SSL3_KEY_MAT_PARAMS object to a CK_SSL3_KEY_MAT_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_SSL3_KEY_MAT_PARAMS object to convert
 * @return - the new CK_SSL3_KEY_MAT_PARAMS structure
 */
CK_SSL3_KEY_MAT_PARAMS jSsl3KeyMatParamToCKSsl3KeyMatParam(JNIEnv *env, jobject jParam)
{
	jclass jSsl3KeyMatParamsClass = (*env)->FindClass(env, CLASS_SSL3_KEY_MAT_PARAMS);
	CK_SSL3_KEY_MAT_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jboolean jBoolean;
	jobject jObject;
	jobject jRandomInfo;
	jobject jReturnedKeyMaterial;
	jclass jSsl3RandomDataClass;
	jclass jSsl3KeyMatOutClass;
	CK_ULONG ckTemp;

	/* get ulMacSizeInBits */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatParamsClass, "ulMacSizeInBits", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulMacSizeInBits = jLongToCKULong(jLong);

	/* get ulKeySizeInBits */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatParamsClass, "ulKeySizeInBits", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulKeySizeInBits = jLongToCKULong(jLong);

	/* get ulIVSizeInBits */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatParamsClass, "ulIVSizeInBits", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulIVSizeInBits = jLongToCKULong(jLong);

	/* get bIsExport */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatParamsClass, "bIsExport", "Z");
	assert(fieldID != 0);
	jBoolean = (*env)->GetBooleanField(env, jParam, fieldID);
	ckParam.bIsExport = jBooleanToCKBBool(jBoolean);

	/* get RandomInfo */
	jSsl3RandomDataClass = (*env)->FindClass(env, CLASS_SSL3_RANDOM_DATA);
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatParamsClass, "RandomInfo", CLASS_NAME(CLASS_SSL3_RANDOM_DATA));
	assert(fieldID != 0);
	jRandomInfo = (*env)->GetObjectField(env, jParam, fieldID);

	/* get pClientRandom and ulClientRandomLength out of RandomInfo */
	fieldID = (*env)->GetFieldID(env, jSsl3RandomDataClass, "pClientRandom", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jRandomInfo, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.RandomInfo.pClientRandom), &(ckParam.RandomInfo.ulClientRandomLen));

	/* get pServerRandom and ulServerRandomLength out of RandomInfo */
	fieldID = (*env)->GetFieldID(env, jSsl3RandomDataClass, "pServerRandom", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jRandomInfo, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.RandomInfo.pServerRandom), &(ckParam.RandomInfo.ulServerRandomLen));

	/* get pReturnedKeyMaterial */
	jSsl3KeyMatOutClass = (*env)->FindClass(env, CLASS_SSL3_KEY_MAT_OUT);
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatParamsClass, "pReturnedKeyMaterial", CLASS_NAME(CLASS_SSL3_KEY_MAT_OUT));
	assert(fieldID != 0);
	jReturnedKeyMaterial = (*env)->GetObjectField(env, jParam, fieldID);

	/* allocate memory for pRetrunedKeyMaterial */
	ckParam.pReturnedKeyMaterial = (CK_SSL3_KEY_MAT_OUT_PTR) malloc(sizeof(CK_SSL3_KEY_MAT_OUT));
  if (ckParam.pReturnedKeyMaterial == NULL_PTR) { throwOutOfMemoryError(env); return ckParam; }

	/* get hClientMacSecret out of pReturnedKeyMaterial */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatOutClass, "hClientMacSecret", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jReturnedKeyMaterial, fieldID);
	ckParam.pReturnedKeyMaterial->hClientMacSecret = jLongToCKULong(jLong);

	/* get hServerMacSecret out of pReturnedKeyMaterial */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatOutClass, "hServerMacSecret", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jReturnedKeyMaterial, fieldID);
	ckParam.pReturnedKeyMaterial->hServerMacSecret = jLongToCKULong(jLong);

	/* get hClientKey out of pReturnedKeyMaterial */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatOutClass, "hClientKey", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jReturnedKeyMaterial, fieldID);
	ckParam.pReturnedKeyMaterial->hClientKey = jLongToCKULong(jLong);

	/* get hServerKey out of pReturnedKeyMaterial */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatOutClass, "hServerKey", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jReturnedKeyMaterial, fieldID);
	ckParam.pReturnedKeyMaterial->hServerKey = jLongToCKULong(jLong);

	/* get pIVClient out of pReturnedKeyMaterial */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatOutClass, "pIVClient", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jReturnedKeyMaterial, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pReturnedKeyMaterial->pIVClient), &ckTemp);

	/* get pIVServer out of pReturnedKeyMaterial */
	fieldID = (*env)->GetFieldID(env, jSsl3KeyMatOutClass, "pIVServer", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jReturnedKeyMaterial, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pReturnedKeyMaterial->pIVServer), &ckTemp);

	return ckParam ;
}

/*
 * converts the Java CK_KEY_DERIVATION_STRING_DATA object to a 
 * CK_KEY_DERIVATION_STRING_DATA structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_KEY_DERIVATION_STRING_DATA object to convert
 * @return - the new CK_KEY_DERIVATION_STRING_DATA structure
 */
CK_KEY_DERIVATION_STRING_DATA jKeyDerivationStringDataToCKKeyDerivationStringData(JNIEnv *env, jobject jParam)
{
	jclass jKeyDerivationStringDataClass = (*env)->FindClass(env, CLASS_KEY_DERIVATION_STRING_DATA);
	CK_KEY_DERIVATION_STRING_DATA ckParam;
	jfieldID fieldID;
	jobject jObject;

  /* get pData */
	fieldID = (*env)->GetFieldID(env, jKeyDerivationStringDataClass, "pData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pData), &(ckParam.ulLen));

	return ckParam ;
}

/*
 * converts the Java CK_RSA_PKCS_PSS_PARAMS object to a CK_RSA_PKCS_PSS_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_RSA_PKCS_PSS_PARAMS object to convert
 * @return - the new CK_RSA_PKCS_PSS_PARAMS structure
 */
CK_RSA_PKCS_PSS_PARAMS jRsaPkcsPssParamToCKRsaPkcsPssParam(JNIEnv *env, jobject jParam)
{
	jclass jRsaPkcsPssParamsClass = (*env)->FindClass(env, CLASS_RSA_PKCS_PSS_PARAMS);
	CK_RSA_PKCS_PSS_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;

	/* get hashAlg */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsPssParamsClass, "hashAlg", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.hashAlg = jLongToCKULong(jLong);

	/* get mgf */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsPssParamsClass, "mgf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.mgf = jLongToCKULong(jLong);

	/* get sLen */
	fieldID = (*env)->GetFieldID(env, jRsaPkcsPssParamsClass, "sLen", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.sLen = jLongToCKULong(jLong);

	return ckParam ;
}

/*
 * converts the Java CK_ECDH1_DERIVE_PARAMS object to a CK_ECDH1_DERIVE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_ECDH1_DERIVE_PARAMS object to convert
 * @return - the new CK_ECDH1_DERIVE_PARAMS structure
 */
CK_ECDH1_DERIVE_PARAMS jEcdh1DeriveParamToCKEcdh1DeriveParam(JNIEnv *env, jobject jParam)
{
	jclass jEcdh1DeriveParamsClass = (*env)->FindClass(env, CLASS_ECDH1_DERIVE_PARAMS);
	CK_ECDH1_DERIVE_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;

	/* get kdf */
	fieldID = (*env)->GetFieldID(env, jEcdh1DeriveParamsClass, "kdf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.kdf = jLongToCKULong(jLong);

	/* get pSharedData and ulSharedDataLen */
	fieldID = (*env)->GetFieldID(env, jEcdh1DeriveParamsClass, "pSharedData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pSharedData), &(ckParam.ulSharedDataLen));

	/* get pPublicData and ulPublicDataLen */
	fieldID = (*env)->GetFieldID(env, jEcdh1DeriveParamsClass, "pPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData), &(ckParam.ulPublicDataLen));

	return ckParam ;
}

/*
 * converts the Java CK_ECDH2_DERIVE_PARAMS object to a CK_ECDH2_DERIVE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_ECDH2_DERIVE_PARAMS object to convert
 * @return - the new CK_ECDH2_DERIVE_PARAMS structure
 */
CK_ECDH2_DERIVE_PARAMS jEcdh2DeriveParamToCKEcdh2DeriveParam(JNIEnv *env, jobject jParam)
{
	jclass jEcdh2DeriveParamsClass = (*env)->FindClass(env, CLASS_ECDH2_DERIVE_PARAMS);
	CK_ECDH2_DERIVE_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;

	/* get kdf */
	fieldID = (*env)->GetFieldID(env, jEcdh2DeriveParamsClass, "kdf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.kdf = jLongToCKULong(jLong);

	/* get pSharedData and ulSharedDataLen */
	fieldID = (*env)->GetFieldID(env, jEcdh2DeriveParamsClass, "pSharedData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pSharedData), &(ckParam.ulSharedDataLen));

	/* get pPublicData and ulPublicDataLen */
	fieldID = (*env)->GetFieldID(env, jEcdh2DeriveParamsClass, "pPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData), &(ckParam.ulPublicDataLen));

	/* get ulPrivateDataLen */
	fieldID = (*env)->GetFieldID(env, jEcdh2DeriveParamsClass, "ulPrivateDataLen", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulPrivateDataLen = jLongToCKULong(jLong);

	/* get hPrivateData */
	fieldID = (*env)->GetFieldID(env, jEcdh2DeriveParamsClass, "hPrivateData", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.hPrivateData = jLongToCKULong(jLong);

	/* get pPublicData2 and ulPublicDataLen2 */
	fieldID = (*env)->GetFieldID(env, jEcdh2DeriveParamsClass, "pPublicData2", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData2), &(ckParam.ulPublicDataLen2));

	return ckParam ;
}

/*
 * converts the Java CK_X9_42_DH1_DERIVE_PARAMS object to a CK_X9_42_DH1_DERIVE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_X9_42_DH1_DERIVE_PARAMS object to convert
 * @return - the new CK_X9_42_DH1_DERIVE_PARAMS structure
 */
CK_X9_42_DH1_DERIVE_PARAMS jX942Dh1DeriveParamToCKX942Dh1DeriveParam(JNIEnv *env, jobject jParam)
{
	jclass jX942Dh1DeriveParamsClass = (*env)->FindClass(env, CLASS_X9_42_DH1_DERIVE_PARAMS);
	CK_X9_42_DH1_DERIVE_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;

	/* get kdf */
	fieldID = (*env)->GetFieldID(env, jX942Dh1DeriveParamsClass, "kdf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.kdf = jLongToCKULong(jLong);

	/* get pOtherInfo and ulOtherInfoLen */
	fieldID = (*env)->GetFieldID(env, jX942Dh1DeriveParamsClass, "pOtherInfo", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pOtherInfo), &(ckParam.ulOtherInfoLen));

	/* get pPublicData and ulPublicDataLen */
	fieldID = (*env)->GetFieldID(env, jX942Dh1DeriveParamsClass, "pPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData), &(ckParam.ulPublicDataLen));

	return ckParam ;
}

/*
 * converts the Java CK_X9_42_DH2_DERIVE_PARAMS object to a CK_X9_42_DH2_DERIVE_PARAMS structure
 *
 * @param env - used to call JNI funktions to get the Java classes and objects
 * @param jParam - the Java CK_X9_42_DH2_DERIVE_PARAMS object to convert
 * @return - the new CK_X9_42_DH2_DERIVE_PARAMS structure
 */
CK_X9_42_DH2_DERIVE_PARAMS jX942Dh2DeriveParamToCKX942Dh2DeriveParam(JNIEnv *env, jobject jParam)
{
	jclass jX942Dh2DeriveParamsClass = (*env)->FindClass(env, CLASS_X9_42_DH2_DERIVE_PARAMS);
	CK_X9_42_DH2_DERIVE_PARAMS ckParam;
	jfieldID fieldID;
	jlong jLong;
	jobject jObject;

	/* get kdf */
	fieldID = (*env)->GetFieldID(env, jX942Dh2DeriveParamsClass, "kdf", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.kdf = jLongToCKULong(jLong);

	/* get pOtherInfo and ulOtherInfoLen */
	fieldID = (*env)->GetFieldID(env, jX942Dh2DeriveParamsClass, "pOtherInfo", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pOtherInfo), &(ckParam.ulOtherInfoLen));

	/* get pPublicData and ulPublicDataLen */
	fieldID = (*env)->GetFieldID(env, jX942Dh2DeriveParamsClass, "pPublicData", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData), &(ckParam.ulPublicDataLen));

	/* get ulPrivateDataLen */
	fieldID = (*env)->GetFieldID(env, jX942Dh2DeriveParamsClass, "ulPrivateDataLen", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.ulPrivateDataLen = jLongToCKULong(jLong);

	/* get hPrivateData */
	fieldID = (*env)->GetFieldID(env, jX942Dh2DeriveParamsClass, "hPrivateData", "J");
	assert(fieldID != 0);
	jLong = (*env)->GetLongField(env, jParam, fieldID);
	ckParam.hPrivateData = jLongToCKULong(jLong);

	/* get pPublicData2 and ulPublicDataLen2 */
	fieldID = (*env)->GetFieldID(env, jX942Dh2DeriveParamsClass, "pPublicData2", "[B");
	assert(fieldID != 0);
	jObject = (*env)->GetObjectField(env, jParam, fieldID);
	jByteArrayToCKByteArray(env, jObject, &(ckParam.pPublicData2), &(ckParam.ulPublicDataLen2));

	return ckParam ;
}




/* ************************************************************************** */
/* Functions for keeping track of currently active and loaded modules         */
/* ************************************************************************** */


/*
 * Create a new object for locking.
 */
jobject createLockObject(JNIEnv *env) {
	jclass jObjectClass;
  jobject jLockObject;
  jmethodID jConstructor;

  jObjectClass = (*env)->FindClass(env, "java/lang/Object");
	assert(jObjectClass != 0);
	jConstructor = (*env)->GetMethodID(env, jObjectClass, "<init>", "()V");
	assert(jConstructor != 0);
	jLockObject = (*env)->NewObject(env, jObjectClass, jConstructor);
	assert(jLockObject != 0);
  jLockObject = (*env)->NewGlobalRef(env, jLockObject);

  return jLockObject ;
}

/*
 * Create a new object for locking.
 */
void destroyLockObject(JNIEnv *env, jobject jLockObject) {
	if (jLockObject != NULL_PTR) {
		(*env)->DeleteGlobalRef(env, jLockObject);
	}
}

/*
 * Add the given pkcs11Implementation object to the list of present modules.
 * Attach the given data to the entry. If the given pkcs11Implementation is
 * already in the lsit, just override its old module data with the new one.
 * None of the arguments can be NULL_PTR. If one of the arguments is NULL_PTR, this
 * function does nothing.
 */
void putModuleEntry(JNIEnv *env, jobject pkcs11Implementation, ModuleData *moduleData) {
  ModuleListNode *currentNode, *newNode;

  if (pkcs11Implementation == NULL_PTR) {
    return ;
  }
  if (moduleData == NULL_PTR) {
    return ;
  }

  (*env)->MonitorEnter(env, moduleListLock); /* synchronize access to list */

  if (moduleListHead == NULL_PTR) {
    /* this is the first entry */
    newNode = (ModuleListNode *) malloc(sizeof(ModuleListNode));
    if (newNode == NULL_PTR) { throwOutOfMemoryError(env); return; }
    newNode->pkcs11Implementation = pkcs11Implementation;
    newNode->moduleData = moduleData;
    newNode->next = NULL_PTR;

    moduleListHead = newNode;
  } else {
    /* go to the last entry; i.e. the first node which's 'next' is NULL_PTR.
     * we also stop, when we the pkcs11Implementation object is already in the list.
     * then we override the old moduleData with the new one
     */
    currentNode = moduleListHead;
    while ((currentNode->next != NULL_PTR) && (!equals(env, pkcs11Implementation, currentNode->pkcs11Implementation))) {
      currentNode = currentNode->next;
    }
    if (!equals(env, pkcs11Implementation, currentNode->pkcs11Implementation)) {
      /* this pkcs11Implementation is not present yet, append the new node */
      newNode = (ModuleListNode *) malloc(sizeof(ModuleListNode));
      if (newNode == NULL_PTR) { throwOutOfMemoryError(env); return; }
      newNode->pkcs11Implementation = pkcs11Implementation;
      newNode->moduleData = moduleData;
      newNode->next = NULL_PTR;

      currentNode->next = newNode;
    } else {
      /* this pkcs11Implementation is already present, set the new moduleData */
      currentNode->moduleData = moduleData;
    }
  }

  (*env)->MonitorExit(env, moduleListLock); /* synchronize access to list */
}


/*
 * Get the module data of the entry for the given pkcs11Implementation. Returns
 * NULL_PTR, if the pkcs11Implementation is not in the list.
 */
ModuleData * getModuleEntry(JNIEnv *env, jobject pkcs11Implementation) {
  ModuleListNode *currentNode;
  ModuleData *moduleDataOfFoundNode;

  moduleDataOfFoundNode = NULL_PTR;

  if (pkcs11Implementation == NULL_PTR) {
    /* Nothing to do. */
    return NULL_PTR ;
  }

  /* We stop, when we the pkcs11Implementation object is already in the list.
   * We also stop, when we reach the end; i.e. the first node which's 'next'
   * is NULL_PTR.
   */
  (*env)->MonitorEnter(env, moduleListLock); /* synchronize access to list */

  if (moduleListHead != NULL_PTR) {
    currentNode = moduleListHead;
    while ((currentNode->next != NULL_PTR) && (!equals(env, pkcs11Implementation, currentNode->pkcs11Implementation))) {
      currentNode = currentNode->next;
    }
    if (equals(env, pkcs11Implementation, currentNode->pkcs11Implementation)) {
      /* we found the entry */
      moduleDataOfFoundNode = currentNode->moduleData;
    } else {
      /* the entry is not in the list */
      moduleDataOfFoundNode = NULL_PTR;
    }
  }

  (*env)->MonitorExit(env, moduleListLock); /* synchronize access to list */

  return moduleDataOfFoundNode ;
}


/*
 * Returns 1, if the given pkcs11Implementation is in the list.
 * 0, otherwise.
 */
int isModulePresent(JNIEnv *env, jobject pkcs11Implementation) {
  int present;

  ModuleData *moduleData = getModuleEntry(env, pkcs11Implementation);

  present = (moduleData != NULL_PTR) ? 1 : 0;

  return present ;
}


/*
 * Removes the entry for the given pkcs11Implementation from the list. Returns
 * the module's data, after the node was removed. If this function returns NULL_PTR
 * the pkcs11Implementation was not in the list.
 */
ModuleData * removeModuleEntry(JNIEnv *env, jobject pkcs11Implementation) {
  ModuleListNode *currentNode, *previousNode;
  ModuleData *moduleDataOfFoundNode;

  moduleDataOfFoundNode = NULL_PTR;

  if (pkcs11Implementation == NULL_PTR) {
    /* Nothing to do. */
    return NULL_PTR ;
  }

  /* We stop, when we the pkcs11Implementation object is already in the list.
   * We also stop, when we reach the end; i.e. the first node which's 'next'
   * is NULL_PTR. We remember the previous node the be able to remove the node
   * later.
   */
  (*env)->MonitorEnter(env, moduleListLock); /* synchronize access to list */

  if (moduleListHead != NULL_PTR) {
    currentNode = moduleListHead;
    previousNode = NULL_PTR;
    while ((currentNode->next != NULL_PTR) && (!equals(env, pkcs11Implementation, currentNode->pkcs11Implementation))) {
      previousNode = currentNode;
      currentNode = currentNode->next;
    }
    if (equals(env, pkcs11Implementation, currentNode->pkcs11Implementation)) {
      /* we found the entry, so remove it */
      if (previousNode == NULL_PTR) {
        /* it's the first node */
        moduleListHead = currentNode->next;
      } else {
        previousNode->next = currentNode->next;
      }
      moduleDataOfFoundNode = currentNode->moduleData;
      (*env)->DeleteGlobalRef(env, currentNode->pkcs11Implementation);
      free(currentNode);
    } else {
      /* the entry is not in the list */
      moduleDataOfFoundNode = NULL_PTR ;
    }
  }

  (*env)->MonitorExit(env, moduleListLock); /* synchronize access to list */

  return moduleDataOfFoundNode ;
}

/*
 * Removes all present entries from the list of modules and frees all
 * associated resources. This function is used for clean-up.
 */
void removeAllModuleEntries(JNIEnv *env) {
  ModuleListNode *currentNode, *nextNode;

  (*env)->MonitorEnter(env, moduleListLock); /* synchronize access to list */

  currentNode = moduleListHead;
  while (currentNode != NULL_PTR) {
    nextNode = currentNode->next;
    (*env)->DeleteGlobalRef(env, currentNode->pkcs11Implementation);
    free(currentNode);
    currentNode = nextNode;
  }
  moduleListHead = NULL_PTR;

  (*env)->MonitorExit(env, moduleListLock); /* synchronize access to list */
}


/*
 * This function compares the two given objects using the equals method as
 * implemented by the Object class; i.e. it checks, if both refereces refer
 * to the same object. If both references are NULL_PTR, this functions also regards
 * them as equal.
 */
int equals(JNIEnv *env, jobject thisObject, jobject otherObject) {
	jclass jObjectClass;
	jmethodID jequals;
	jboolean jequal = JNI_FALSE;
  int returnValue;

  if (thisObject != NULL_PTR) {
	  jObjectClass = (*env)->FindClass(env, "java/lang/Object");
	  assert(jObjectClass != 0);
	  jequals = (*env)->GetMethodID(env, jObjectClass, "equals", "(Ljava/lang/Object;)Z");
	  assert(jequals != 0);
    /* We must call the equals method as implemented by the Object class. This
     * method compares if both references refer to the same object. This is what
     * we want.
     */
    jequal = (*env)->CallNonvirtualBooleanMethod(env, thisObject, jObjectClass, jequals, otherObject);
  } else if (otherObject == NULL_PTR) {
    jequal = JNI_TRUE; /* both NULL_PTR, we regard equal */
  }

  returnValue = (jequal == JNI_TRUE) ? 1 : 0;

  return returnValue ;
}


/* ************************************************************************** */
/* Functions for keeping track of notify callbacks                            */
/* ************************************************************************** */

#ifndef NO_CALLBACKS

/*
 * Add the given notify encapsulation object to the list of active notify
 * objects.
 * If notifyEncapsulation is NULL_PTR, this function does nothing.
 */
void putNotifyEntry(JNIEnv *env, CK_SESSION_HANDLE hSession, NotifyEncapsulation *notifyEncapsulation) {
  NotifyListNode *currentNode, *newNode;

  if (notifyEncapsulation == NULL_PTR) {
    return ;
  }

  newNode = (NotifyListNode *) malloc(sizeof(NotifyListNode));
  if (newNode == NULL_PTR) { throwOutOfMemoryError(env); return; }
  newNode->hSession = hSession;
  newNode->notifyEncapsulation = notifyEncapsulation;
  newNode->next = NULL_PTR;

  (*env)->MonitorEnter(env, notifyListLock); /* synchronize access to list */

  if (notifyListHead == NULL_PTR) {
    /* this is the first entry */
    notifyListHead = newNode;
  } else {
    /* go to the last entry; i.e. the first node which's 'next' is NULL_PTR.
     */
    currentNode = notifyListHead;
    while (currentNode->next != NULL_PTR) {
      currentNode = currentNode->next;
    }
    currentNode->next = newNode;
  }

  (*env)->MonitorExit(env, notifyListLock); /* synchronize access to list */
}


/*
 * Removes the active notifyEncapsulation object used with the given session and
 * returns it. If there is no notifyEncapsulation active for this session, this
 * function returns NULL_PTR.
 */
NotifyEncapsulation * removeNotifyEntry(JNIEnv *env, CK_SESSION_HANDLE hSession) {
  NotifyEncapsulation *notifyEncapsulation;
  NotifyListNode *currentNode, *previousNode;

  (*env)->MonitorEnter(env, notifyListLock); /* synchronize access to list */

  if (notifyListHead == NULL_PTR) {
    /* this is the first entry */
    notifyEncapsulation = NULL_PTR;
  } else {
    /* Find the node with the wanted session handle. Also stop, when we reach
     * the last entry; i.e. the first node which's 'next' is NULL_PTR.
     */
    currentNode = notifyListHead;
    previousNode = NULL_PTR;

    while ((currentNode->hSession != hSession) && (currentNode->next != NULL_PTR)) {
      previousNode = currentNode;
      currentNode = currentNode->next;
    }

    if (currentNode->hSession == hSession) {
      /* We found a entry for the wanted session, now remove it. */
      if (previousNode == NULL_PTR) {
        /* it's the first node */
        notifyListHead = currentNode->next;
      } else {
        previousNode->next = currentNode->next;
      }
      notifyEncapsulation = currentNode->notifyEncapsulation;
      free(currentNode);
    } else {
      /* We did not find a entry for this session */
      notifyEncapsulation = NULL_PTR;
    }
  }

  (*env)->MonitorExit(env, notifyListLock); /* synchronize access to list */

  return notifyEncapsulation ;
}

/*

 * Removes the first notifyEncapsulation object. If there is no notifyEncapsulation,
 * this function returns NULL_PTR.
 */
NotifyEncapsulation * removeFirstNotifyEntry(JNIEnv *env) {
  NotifyEncapsulation *notifyEncapsulation;
  NotifyListNode *currentNode;

  (*env)->MonitorEnter(env, notifyListLock); /* synchronize access to list */

  if (notifyListHead == NULL_PTR) {
    /* this is the first entry */
    notifyEncapsulation = NULL_PTR;
  } else {
    /* Remove the first entry. */
    currentNode = notifyListHead;
    notifyListHead = notifyListHead->next;
    notifyEncapsulation = currentNode->notifyEncapsulation;
    free(currentNode);
  }

  (*env)->MonitorExit(env, notifyListLock); /* synchronize access to list */

  return notifyEncapsulation ;
}

#endif /* NO_CALLBACKS */
