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
 * pkcs11wrapper.h
 * 18.05.2001
 *
 * declaration of all functions used by pkcs11wrapper.c
 *
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 * @author Martin Schl�ffer <schlaeff@sbox.tugraz.at>
 */


/* incldue the platform dependent part of the header */
#include "platform.h"

#include "pkcs11.h"
#include "jni.h"
#include "iaik_pkcs_pkcs11_wrapper_PKCS11Implementation.h"

#include <time.h>

#define ckBBoolToJBoolean(x) (x == TRUE) ? JNI_TRUE : JNI_FALSE;
#define jBooleanToCKBBool(x) (x == JNI_TRUE) ? TRUE : FALSE;

#define ckByteToJByte(x) (jbyte) x
/*#define ckBytePtrToJBytePtr(x) (jbyte *) x */
#define jByteToCKByte(x) (CK_BYTE) x
/*#define jBytePtrToCKBytePtr(x) (CK_BYTE *) x */

#define ckLongToJLong(x) (jlong) x
/*#define ckLongPtrToJLongPtr(x) (jlong *) x */
#define jLongToCKLong(x) (CK_LONG) x
/*#define jLongPtrToCKLongPtr(x) (CK_LONG *) x */

#define ckULongToJLong(x) (jlong) x
/*#define ckULongPtrToJLongPtr(x) (jlong *) x */
#define jLongToCKULong(x) (CK_ULONG) x
/*#define jLongPtrToCKULongPtr(x) (CK_ULONG *) x */

#define ckCharToJChar(x) (jchar) x
/*#define ckCharPtrToJCharPtr(x) (jchar *) x */
#define jCharToCKChar(x) (CK_CHAR) x
/*#define jCharPtrToCKCharPtr(x) (CK_CHAR *) x */

#define ckUTF8CharToJChar(x) (jchar) x
/*#define ckUTF8CharPtrToJCharPtr(x) (jchar *) x */
#define jCharToCKUTF8Char(x) (CK_UTF8CHAR) x
/*#define jCharPtrToCKUTF8CharPtr(x) (CK_UTF8CHAR *) x */

#define ckUTF8CharToJByte(x) (jbyte) x
#define jByteToCKUTF8Char(x) (CK_UTF8CHAR) x

#define ckFlageToJLong(x) (jlong) x
/*#define ckFlagsPtrToJLongPtr(x) (jlong *) x */
/*#define jLongToCKFlags(x) (CK_FLAGS) x */
/*#define jLongPtrToCKFlagsPtr(x) (CK_FLAGS *) x */

#define ckVoidPtrToJObject(x) (jobject) x
#define jObjectToCKVoidPtr(x) (CK_VOID_PTR) x

#define jIntToCKLong(x) (CK_LONG) x
#define jIntToCKULong(x) (CK_ULONG) x
#define ckLongToJInt(x) (jint) x
#define ckULongToJInt(x) (jint) x
#define ckULongToJSize(x) (jsize) x
#define unsignedIntToCKULong(x) (CK_ULONG) x

/*
 * These are tags used for the logger.
 */
#define tag_call "CALL"
#define tag_debug "DEBUG"
#define tag_info "INFO"
#define tag_error "ERROR"

/*
 * This methods prints log entries with the following format:
 * <timestamp> <tag>: <message> (<method>)
 */
#ifdef DEBUG
void timeStamp() {
	char stamp[20];
	time_t now;
	struct tm *noww;
	now =  time(NULL);
	noww = localtime(&now);
	strftime(stamp, 20, "%x %X", noww);
	stamp[19] = '\0';
	printf("%s ", stamp);
}
#define buffer_size = 50;
#define TRACE0(tag, method, message) { timeStamp(); printf("%6s: ", tag); printf(message); printf(" (in %s)\n", method); fflush(stdout); }
#define TRACE1(tag, method, message, p1) { timeStamp(); printf("%6s: ", tag); printf(message, p1); printf(" (in %s)\n", method); fflush(stdout); }
#define TRACE2(tag, method, message, p1, p2) { timeStamp(); printf("%6s: ", tag); printf(message, p1, p2); printf(" (in %s)\n", method); fflush(stdout); }
#define TRACE3(tag, method, message, p1, p2, p3) { timeStamp(); printf("%6s: ", tag); printf(message, p1, p2, p3); printf(" (in %s)\n", method); fflush(stdout); }
#else
#define TRACE0(tag, method, message)
#define TRACE1(tag, method, message, p1)
#define TRACE2(tag, method, message, p1, p2)
#define TRACE3(tag, method, message, p1, p2, p3)
#define TRACE_INTEND
#define TRACE_UNINTEND
#endif

#define CK_ASSERT_OK 0L
#ifndef CKR_PIN_INCORRECT
#define CKR_PIN_INCORRECT 160L
#endif

#define CLASS_INFO "iaik/pkcs/pkcs11/wrapper/CK_INFO"
#define CLASS_VERSION "iaik/pkcs/pkcs11/wrapper/CK_VERSION"
#define CLASS_SLOT_INFO "iaik/pkcs/pkcs11/wrapper/CK_SLOT_INFO"
#define CLASS_TOKEN_INFO "iaik/pkcs/pkcs11/wrapper/CK_TOKEN_INFO"
#define CLASS_MECHANISM "iaik/pkcs/pkcs11/wrapper/CK_MECHANISM"
#define CLASS_MECHANISM_INFO "iaik/pkcs/pkcs11/wrapper/CK_MECHANISM_INFO"
#define CLASS_SESSION_INFO "iaik/pkcs/pkcs11/wrapper/CK_SESSION_INFO"
#define CLASS_ATTRIBUTE "iaik/pkcs/pkcs11/wrapper/CK_ATTRIBUTE"
#define CLASS_DATE "iaik/pkcs/pkcs11/wrapper/CK_DATE"
#define CLASS_PKCS11EXCEPTION "iaik/pkcs/pkcs11/wrapper/PKCS11Exception"
#define CLASS_PKCS11RUNTIMEEXCEPTION "iaik/pkcs/pkcs11/wrapper/PKCS11RuntimeException"
#define CLASS_FILE_NOT_FOUND_EXCEPTION "java/io/FileNotFoundException"
#define CLASS_OUT_OF_MEMORY_ERROR "java/lang/OutOfMemoryError"
#define CLASS_IO_EXCEPTION "java/io/IOException"
#define CLASS_C_INITIALIZE_ARGS "iaik/pkcs/pkcs11/wrapper/CK_C_INITIALIZE_ARGS"
#define CLASS_CREATEMUTEX "iaik/pkcs/pkcs11/wrapper/CK_CREATEMUTEX"
#define CLASS_DESTROYMUTEX "iaik/pkcs/pkcs11/wrapper/CK_DESTROYMUTEX"
#define CLASS_LOCKMUTEX "iaik/pkcs/pkcs11/wrapper/CK_LOCKMUTEX"
#define CLASS_UNLOCKMUTEX "iaik/pkcs/pkcs11/wrapper/CK_UNLOCKMUTEX"
#define CLASS_NOTIFY "iaik/pkcs/pkcs11/wrapper/CK_NOTIFY"
#define CLASS_PKCS11UTIL "iaik/pkcs/pkcs11/wrapper/PKCS11UTIL"
#define METHOD_ENCODER "utf8Encoder"
#define METHOD_DECODER "utf8Decoder"

/* mechanism parameter classes */

#define CLASS_RSA_PKCS_OAEP_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RSA_PKCS_OAEP_PARAMS"
#define CLASS_KEA_DERIVE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_KEA_DERIVE_PARAMS"
#define CLASS_RC2_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RC2_PARAMS"
#define CLASS_RC2_CBC_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RC2_CBC_PARAMS"
#define CLASS_RC2_MAC_GENERAL_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RC2_MAC_GENERAL_PARAMS"
#define CLASS_RC5_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RC5_PARAMS"
#define CLASS_RC5_CBC_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RC5_CBC_PARAMS"
#define CLASS_RC5_MAC_GENERAL_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RC5_MAC_GENERAL_PARAMS"
#define CLASS_MAC_GENERAL_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_MAC_GENERAL_PARAMS"
#define CLASS_SKIPJACK_PRIVATE_WRAP_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_SKIPJACK_PRIVATE_WRAP_PARAMS"
#define CLASS_SKIPJACK_RELAYX_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_SKIPJACK_RELAYX_PARAMS"
#define CLASS_PBE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_PBE_PARAMS"
#define PBE_INIT_VECTOR_SIZE 8
#define CLASS_PKCS5_PBKD2_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_PKCS5_PBKD2_PARAMS"
#define CLASS_KEY_WRAP_SET_OAEP_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_KEY_WRAP_SET_OAEP_PARAMS"
#define CLASS_KEY_DERIVATION_STRING_DATA "iaik/pkcs/pkcs11/wrapper/CK_KEY_DERIVATION_STRING_DATA"
#define CLASS_SSL3_RANDOM_DATA "iaik/pkcs/pkcs11/wrapper/CK_SSL3_RANDOM_DATA"
/* CLASS_SSL3_RANDOM_DATA is used by CLASS_SSL3_MASTER_KEY_DERIVE_PARAMS */
#define CLASS_SSL3_KEY_MAT_OUT "iaik/pkcs/pkcs11/wrapper/CK_SSL3_KEY_MAT_OUT"
/* CLASS_SSL3_KEY_MAT_OUT is used by CLASS_SSL3_KEY_MAT_PARAMS */
#define CLASS_SSL3_MASTER_KEY_DERIVE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_SSL3_MASTER_KEY_DERIVE_PARAMS"
#define CLASS_SSL3_KEY_MAT_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_SSL3_KEY_MAT_PARAMS"
#define CLASS_EXTRACT_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_EXTRACT_PARAMS"

#define CLASS_RSA_PKCS_PSS_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_RSA_PKCS_PSS_PARAMS"
#define CLASS_ECDH1_DERIVE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_ECDH1_DERIVE_PARAMS"
#define CLASS_ECDH2_DERIVE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_ECDH2_DERIVE_PARAMS"
#define CLASS_X9_42_DH1_DERIVE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_X9_42_DH1_DERIVE_PARAMS"
#define CLASS_X9_42_DH2_DERIVE_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_X9_42_DH2_DERIVE_PARAMS"

#define CLASS_DES_CBC_ENCRYPT_DATA_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_DES_CBC_ENCRYPT_DATA_PARAMS"
#define CLASS_AES_CBC_ENCRYPT_DATA_PARAMS "iaik/pkcs/pkcs11/wrapper/CK_AES_CBC_ENCRYPT_DATA_PARAMS"

#define CLASS_NAME(clazz) "L"clazz";"

/* function to convert a PKCS#11 return value other than CK_OK into a Java Exception
 * or to throw a PKCS11RuntimeException
 */

jlong ckAssertReturnValueOK(JNIEnv *env, CK_RV returnValue, const char* callerMethodName);
void throwOutOfMemoryError(JNIEnv *env);
void throwPKCS11RuntimeException(JNIEnv *env, jstring jmessage);
void throwFileNotFoundException(JNIEnv *env, jstring jmessage);
void throwIOException(JNIEnv *env, const char *message);
void throwIOExceptionUnicodeMessage(JNIEnv *env, const unsigned short *message);
void throwDisconnectedRuntimeException(JNIEnv *env);

/* funktions to convert Java arrays to a CK-type array and the array length */

int jBooleanArrayToCKBBoolArray(JNIEnv *env, const jbooleanArray jArray, CK_BBOOL **ckpArray, CK_ULONG_PTR ckLength);
int jByteArrayToCKByteArray(JNIEnv *env, const jbyteArray jArray, CK_BYTE_PTR *ckpArray, CK_ULONG_PTR ckLength);
int jLongArrayToCKULongArray(JNIEnv *env, const jlongArray jArray, CK_ULONG_PTR *ckpArray, CK_ULONG_PTR ckLength);
int jCharArrayToCKCharArray(JNIEnv *env, const jcharArray jArray, CK_CHAR_PTR *ckpArray, CK_ULONG_PTR ckLength);
int jCharArrayToCKUTF8CharArray(JNIEnv *env, const jcharArray jArray, CK_UTF8CHAR_PTR *ckpArray, CK_ULONG_PTR ckLength);
int jStringToCKUTF8CharArray(JNIEnv *env, const jstring jArray, CK_UTF8CHAR_PTR *ckpArray, CK_ULONG_PTR ckpLength);
int jAttributeArrayToCKAttributeArray(JNIEnv *env, jobjectArray jAArray, CK_ATTRIBUTE_PTR *ckpArray, CK_ULONG_PTR ckpLength, jboolean jUseUtf8);
/*void jObjectArrayToCKVoidPtrArray(JNIEnv *env, const jobjectArray jArray, CK_VOID_PTR_PTR ckpArray, CK_ULONG_PTR ckpLength); */


/* funktions to convert a CK-type array and the array length to a Java array */

jcharArray ckByteArrayToJByteArray(JNIEnv *env, const CK_BYTE_PTR ckpArray, CK_ULONG ckLength);
jlongArray ckULongArrayToJLongArray(JNIEnv *env, const CK_ULONG_PTR ckpArray, CK_ULONG ckLength);
jcharArray ckCharArrayToJCharArray(JNIEnv *env, const CK_CHAR_PTR ckpArray, CK_ULONG length);
jcharArray ckUTF8CharArrayToJCharArray(JNIEnv *env, const CK_UTF8CHAR_PTR ckpArray, CK_ULONG ckLength);


/* funktions to convert a CK-type structure or a pointer to a CK-value to a Java object */

jobject ckBBoolPtrToJBooleanObject(JNIEnv *env, const CK_BBOOL* ckpValue);
jobject ckULongPtrToJLongObject(JNIEnv *env, const CK_ULONG_PTR ckpValue);
jobject ckDatePtrToJDateObject(JNIEnv *env, const CK_DATE *ckpValue);
jobject ckVersionPtrToJVersion(JNIEnv *env, const CK_VERSION_PTR ckpVersion);
jobject ckInfoPtrToJInfo(JNIEnv *env, const CK_INFO_PTR ckpInfo);
jobject ckSlotInfoPtrToJSlotInfo(JNIEnv *env, const CK_SLOT_INFO_PTR ckpSlotInfo);
jobject ckTokenInfoPtrToJTokenInfo(JNIEnv *env, const CK_TOKEN_INFO_PTR ckpTokenInfo);
jobject ckSessionInfoPtrToJSessionInfo(JNIEnv *env, const CK_SESSION_INFO_PTR ckpSessionInfo);
jobject ckMechanismInfoPtrToJMechanismInfo(JNIEnv *env, const CK_MECHANISM_INFO_PTR ckpMechanismInfo);
jobject ckAttributePtrToJAttribute(JNIEnv *env, const CK_ATTRIBUTE_PTR ckpAttribute, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jboolean jUseUtf8);
jobject ckAttributeArrayToJAttributeArray(JNIEnv *env, const CK_ATTRIBUTE_PTR ckpArray, CK_ULONG ckLength, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jboolean jUseUtf8);


/* funktion to convert the CK-value used by the CK_ATTRIBUTE structure to a Java object */

jobject ckAttributeValueToJObject(JNIEnv *env, const CK_ATTRIBUTE_PTR ckpAttribute, jobject obj, jlong jSessionHandle, jlong jObjectHandle, jboolean jUseUtf8);


/* funktions to convert a Java object to a CK-type structure or a pointer to a CK-value */

CK_BBOOL* jBooleanObjectToCKBBoolPtr(JNIEnv *env, jobject jObject);
CK_BYTE_PTR jByteObjectToCKBytePtr(JNIEnv *env, jobject jObject);
CK_ULONG* jIntegerObjectToCKULongPtr(JNIEnv *env, jobject jObject);
CK_ULONG* jLongObjectToCKULongPtr(JNIEnv *env, jobject jObject);
CK_CHAR_PTR jCharObjectToCKCharPtr(JNIEnv *env, jobject jObject);
CK_VERSION_PTR jVersionToCKVersionPtr(JNIEnv *env, jobject jVersion);
CK_DATE * jDateObjectPtrToCKDatePtr(JNIEnv *env, jobject jDate);
CK_ATTRIBUTE jAttributeToCKAttribute(JNIEnv *env, jobject jAttribute, jboolean jUseUtf8);
CK_MECHANISM jMechanismToCKMechanism(JNIEnv *env, jobject jMechanism, jboolean jUseUtf8);


/* funktions to convert Java objects used by the Mechanism and Attribute class to a CK-type structure */

void jObjectToPrimitiveCKObjectPtrPtr(JNIEnv *env, jobject jObject, CK_VOID_PTR *ckpObjectPtr, CK_ULONG *pLength, jboolean jUseUtf8);
void jMechanismParameterToCKMechanismParameter(JNIEnv *env, jobject jParam, CK_VOID_PTR *ckpParamPtr, CK_ULONG *ckpLength, jboolean jUseUtf8);
void freeCKMechanismParameter(CK_MECHANISM_PTR mechanism);


/* functions to convert a specific Java mechanism parameter object to a CK-mechanism parameter structure */

CK_RSA_PKCS_OAEP_PARAMS jRsaPkcsOaepParamToCKRsaPkcsOaepParam(JNIEnv *env, jobject jParam);
CK_KEA_DERIVE_PARAMS jKeaDeriveParamToCKKeaDeriveParam(JNIEnv *env, jobject jParam);
CK_RC2_CBC_PARAMS jRc2CbcParamToCKRc2CbcParam(JNIEnv *env, jobject jParam);
CK_RC2_MAC_GENERAL_PARAMS jRc2MacGeneralParamToCKRc2MacGeneralParam(JNIEnv *env, jobject jParam);
CK_RC5_PARAMS jRc5ParamToCKRc5Param(JNIEnv *env, jobject jParam);
CK_RC5_CBC_PARAMS jRc5CbcParamToCKRc5CbcParam(JNIEnv *env, jobject jParam);
CK_RC5_MAC_GENERAL_PARAMS jRc5MacGeneralParamToCKRc5MacGeneralParam(JNIEnv *env, jobject jParam);
CK_SKIPJACK_PRIVATE_WRAP_PARAMS jSkipjackPrivateWrapParamToCKSkipjackPrivateWrapParam(JNIEnv *env, jobject jParam);
CK_SKIPJACK_RELAYX_PARAMS jSkipjackRelayxParamToCKSkipjackRelayxParam(JNIEnv *env, jobject jParam);
CK_PBE_PARAMS jPbeParamToCKPbeParam(JNIEnv *env, jobject jParam);
void copyBackPBEInitializationVector(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism);
CK_PKCS5_PBKD2_PARAMS jPkcs5Pbkd2ParamToCKPkcs5Pbkd2Param(JNIEnv *env, jobject jParam);
CK_KEY_WRAP_SET_OAEP_PARAMS jKeyWrapSetOaepParamToCKKeyWrapSetOaepParam(JNIEnv *env, jobject jParam);
void copyBackSetUnwrappedKey(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism);
CK_SSL3_MASTER_KEY_DERIVE_PARAMS jSsl3MasterKeyDeriveParamToCKSsl3MasterKeyDeriveParam(JNIEnv *env, jobject jParam);
void copyBackClientVersion(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism);
CK_SSL3_KEY_MAT_PARAMS jSsl3KeyMatParamToCKSsl3KeyMatParam(JNIEnv *env, jobject jParam);
void copyBackSSLKeyMatParams(JNIEnv *env, CK_MECHANISM *ckMechanism, jobject jMechanism);
CK_KEY_DERIVATION_STRING_DATA jKeyDerivationStringDataToCKKeyDerivationStringData(JNIEnv *env, jobject jParam);
CK_RSA_PKCS_PSS_PARAMS jRsaPkcsPssParamToCKRsaPkcsPssParam(JNIEnv *env, jobject jParam);
CK_ECDH1_DERIVE_PARAMS jEcdh1DeriveParamToCKEcdh1DeriveParam(JNIEnv *env, jobject jParam);
CK_ECDH2_DERIVE_PARAMS jEcdh2DeriveParamToCKEcdh2DeriveParam(JNIEnv *env, jobject jParam);
CK_X9_42_DH1_DERIVE_PARAMS jX942Dh1DeriveParamToCKX942Dh1DeriveParam(JNIEnv *env, jobject jParam);
CK_X9_42_DH2_DERIVE_PARAMS jX942Dh2DeriveParamToCKX942Dh2DeriveParam(JNIEnv *env, jobject jParam);

CK_DES_CBC_ENCRYPT_DATA_PARAMS jDesCbcEncryptDataParamToCKDesCbcEncryptData(JNIEnv *env, jobject jParam);
CK_AES_CBC_ENCRYPT_DATA_PARAMS jAesCbcEncryptDataParamToCKAesCbcEncryptData(JNIEnv *env, jobject jParam);

/* functions to convert the InitArgs object for calling the right Java mutex functions */

CK_C_INITIALIZE_ARGS_PTR makeCKInitArgsAdapter(JNIEnv *env, jobject pInitArgs, jboolean jUseUtf8);

#ifndef NO_CALLBACKS /* if the library should not make callbacks; e.g. no javai.lib or jvm.lib available */
CK_RV callJCreateMutex(CK_VOID_PTR_PTR ppMutex);
CK_RV callJDestroyMutex(CK_VOID_PTR pMutex);
CK_RV callJLockMutex(CK_VOID_PTR pMutex);
CK_RV callJUnlockMutex(CK_VOID_PTR pMutex);
#endif /* NO_CALLBACKS */


/* A node of the list of connected modules */
struct ModuleListNode {

  /* Reference to the object that implements the PKCS11 interface. */
  jobject pkcs11Implementation;

  /* Reference to this PKCS11 object's data. */
  ModuleData *moduleData;

  /* Pointer to the next node in the list. */
  struct ModuleListNode *next;

};
typedef struct ModuleListNode ModuleListNode;


void putModuleEntry(JNIEnv *env, jobject pkcs11Implementation, ModuleData *moduleData);
ModuleData * getModuleEntry(JNIEnv *env, jobject pkcs11Implementation);
int isModulePresent(JNIEnv *env, jobject pkcs11Implementation);
ModuleData * removeModuleEntry(JNIEnv *env, jobject pkcs11Implementation);
void removeAllModuleEntries(JNIEnv *env);
int equals(JNIEnv *env, jobject thisObject, jobject otherObject);


/* A structure to encapsulate the required data for a Notify callback */
struct NotifyEncapsulation {

  /* The object that implements the CK_NOTIFY interface and which should be
   * notified.
   */
  jobject jNotifyObject;

  /* The data object to pass back to the Notify object upon callback. */
  jobject jApplicationData;
};
typedef struct NotifyEncapsulation NotifyEncapsulation;

/* The function for handling notify callbacks. */
CK_RV notifyCallback(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);


/* A node of the list of notify callbacks. To be able to free the resources after use. */
struct NotifyListNode {

  /* The handle of the session this notify object is attached to*/
  CK_SESSION_HANDLE hSession;

  /* Reference to the Notify encapsulation object that was passed to C_OpenSession. */
  NotifyEncapsulation *notifyEncapsulation;

  /* Pointer to the next node in the list. */
  struct NotifyListNode *next;

};
typedef struct NotifyListNode NotifyListNode;

void putNotifyEntry(JNIEnv *env, CK_SESSION_HANDLE hSession, NotifyEncapsulation *notifyEncapsulation);
NotifyEncapsulation * removeNotifyEntry(JNIEnv *env, CK_SESSION_HANDLE hSession);
NotifyEncapsulation * removeFirstNotifyEntry(JNIEnv *env);

jobject createLockObject(JNIEnv *env);
void destroyLockObject(JNIEnv *env, jobject jLockObject);
