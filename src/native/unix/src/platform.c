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
 * This module contains the native functions of the Java to PKCS#11 interface
 * which are platform dependent. This includes loading a dynamic link libary,
 * retrieving the function list and unloading the dynamic link library.
 *
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <jni.h>


/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    connect
 * Signature: (Ljava/lang/String;)V
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_connect
	(JNIEnv *env, jobject obj, jstring jPkcs11ModulePath)
{
  void *hModule;
  char *error;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_RV rv;
  ModuleData *moduleData;
  jobject globalPKCS11ImplementationReference;
  const char *systemErrorMessage;
  char *exceptionMessage;

  const char *libraryNameStr = (*env)->GetStringUTFChars(env, jPkcs11ModulePath, 0);
  TRACE0(tag_call, __FUNCTION__, "entering");
  TRACE1(tag_info, __FUNCTION__, "connecting to PKCS#11 module: %s ... ", libraryNameStr);

  /*
   * Load the PKCS #11 DLL
   */
  dlerror(); /* clear any old error message not fetched */
#ifdef DEBUG
  hModule = dlopen(libraryNameStr, RTLD_NOW);
#else
  hModule = dlopen(libraryNameStr, RTLD_LAZY);
#endif /* DEBUG */

  if (hModule == NULL_PTR) {
    systemErrorMessage = dlerror();
    exceptionMessage = (char *) malloc(sizeof(char) * (strlen(systemErrorMessage) + 1));
    strcpy(exceptionMessage, systemErrorMessage);
    throwIOException(env, exceptionMessage);
    (*env)->ReleaseStringUTFChars(env, jPkcs11ModulePath, libraryNameStr);
    free(exceptionMessage);
    /* free(systemErrorMessage); return values from dlerror() must not be freed! */
    return;
  }

  /*
   * Get function pointer to C_GetFunctionList
   */
  dlerror(); /* clear any old error message not fetched */
  C_GetFunctionList = (CK_C_GetFunctionList) dlsym(hModule, "C_GetFunctionList");
  if ((C_GetFunctionList == NULL_PTR) || ((systemErrorMessage = dlerror()) != NULL_PTR)){
    throwIOException(env, systemErrorMessage);
    /* free(systemErrorMessage); return values from dlerror() must not be freed! */
    return;
  }

  /*
   * Get function pointers to all PKCS #11 functions
   */
  moduleData = (ModuleData *) malloc(sizeof(ModuleData));
  moduleData->hModule = hModule;
  moduleData->applicationMutexHandler = NULL_PTR;
  rv = (C_GetFunctionList)(&(moduleData->ckFunctionListPtr));
  ckAssertReturnValueOK(env, rv, __FUNCTION__);

  globalPKCS11ImplementationReference = (*env)->NewGlobalRef(env, obj);
  putModuleEntry(env, globalPKCS11ImplementationReference, moduleData);

  (*env)->ReleaseStringUTFChars(env, jPkcs11ModulePath, libraryNameStr);
  TRACE0(tag_call, __FUNCTION__,"exiting");
}

/*
 * Class:     iaik_pkcs_pkcs11_wrapper_PKCS11Implementation
 * Method:    disconnect
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_iaik_pkcs_pkcs11_wrapper_PKCS11Implementation_disconnect
	(JNIEnv *env, jobject obj)
{
  ModuleData *moduleData;
  TRACE0(tag_call, __FUNCTION__,"entering");
  TRACE0(tag_debug, __FUNCTION__,"disconnecting module...");
  moduleData = removeModuleEntry(env, obj);

	if (moduleData != NULL_PTR) {
		dlclose(moduleData->hModule);
	}

  free(moduleData);
  TRACE0(tag_call, __FUNCTION__,"exiting");
}
