// Copyright (c) 2002 Graz University of Technology. All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
// 
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
// 
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
// 
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from this
//    software without prior written permission.
// 
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
// 
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * Objects that implement this interface can be used in the InitializeArgs to handle mutex
 * functionality.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public interface MutexHandler {

  /**
   * Create a new mutex object.
   * 
   * @return The new mutex object.
   * @exception PKCS11Exception
   *              If the wrapper should return a differnet value than CKR_OK to the library. It gets
   *              the error-code and returns it as CK_RV.
   * 
   * @postconditions (result <> null)
   */
  public Object createMutex() throws PKCS11Exception;

  /**
   * Destroy a mutex object.
   * 
   * @param mutex
   *          The mutex object to destroy.
   * @exception PKCS11Exception
   *              If the wrapper should return a differnet value than CKR_OK to the library. It gets
   *              the error-code and returns it as CK_RV.
   * @preconditions (mutex <> null)
   * 
   */
  public void destroyMutex(Object mutex) throws PKCS11Exception;

  /**
   * If this method is called on with a mutex object which is not locked, the calling thread obtains
   * a lock on that mutex object and returns. If this method is called with a mutex object which is
   * locked by some thread other than the calling thread, the calling thread blocks and waits for
   * that mutex to be unlocked. If this method is called with a a mutex object which is locked by
   * the calling + thread, the behavior of this method call is undefined.
   * 
   * @param mutex
   *          The mutex object to lock.
   * @exception PKCS11Exception
   *              If the wrapper should return a differnet value than CKR_OK to the library. It gets
   *              the error-code and returns it as CK_RV.
   * @preconditions (mutex <> null)
   * 
   */
  public void lockMutex(Object mutex) throws PKCS11Exception;

  /**
   * If this method is called with a mutex object which is locked by the calling thread, that mutex
   * object is unlocked and the function call returns. Furthermore: If exactly one thread was
   * blocking on that particular mutex object, then that thread stops blocking, obtains a lock on
   * that mutex object, and its lockMutex(Object) call returns. If more than one thread was blocking
   * on that particular mutex objet, then exactly one of the blocking threads is selected somehow.
   * That lucky thread stops blocking, obtains a lock on the mutex object, and its lockMutex(Object)
   * call returns. All other threads blocking on that particular mutex object continue to block. If
   * this method is called with a mutex object which is not locked, then the method call throws an
   * exception with the error code PKCS11Constants.CKR_MUTEX_NOT_LOCKED. If this method is called
   * with a mutex object which is locked by some thread other than the calling thread, the behavior
   * of this method call is undefined.
   * 
   * @param mutex
   *          The mutex object to unlock.
   * @exception PKCS11Exception
   *              If the wrapper should return a differnet value than CKR_OK to the library. It gets
   *              the error-code and returns it as CK_RV.
   * @preconditions (mutex <> null)
   * 
   */
  public void unlockMutex(Object mutex) throws PKCS11Exception;

}
