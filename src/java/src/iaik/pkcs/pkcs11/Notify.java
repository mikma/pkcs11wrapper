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

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * Interface for notification callbacks. Object implementing this interface can be passed to the
 * openSession method of a token.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public interface Notify {

  /**
   * This is the code to return in a PKCS11Exception to signal surrender to the library.
   */
  public static final long CANCEL = PKCS11Constants.CKR_CANCEL;

  /**
   * The module calls this method in certain events. 'Surrender' is the only event defined by now.
   * If the application wants to return an error code, it can do this using PKCS11Exceptions.
   * Throwing no exception means a return value of CKR_OK, and trowing an PKCS11Exception means a
   * return value of the error code of the exception; e.g.<code><br>
   * throw new PKCS11Exception(PKCS11Constants.CKR_CANCEL);<br>
   * </code><br>
   * causes a return value of CKR_CANCEL.
   * 
   * @param session
   *          The session performing the callback.
   * @param surrender
   *          See CK_NOTIFICATION in PKCS#11. A return value of CKR_OK is generatd, if this method
   *          call returns regularly. CKR_CANCEL can be returned to the module by throwing a
   *          PKCS11Exception with the error-code CKR_CANCEL.
   * @param application
   *          The application-object passed to openSession.
   * @exception PKCS11Exception
   *              If the method fails for some reason, or as PKCS11Exception with error-code
   *              CKR_CANCEL to signal the module to cancel the ongoing operation.
   * @preconditions (session <> null)
   * 
   */
  public void notify(Session session, boolean surrender, Object application)
      throws PKCS11Exception;

}
