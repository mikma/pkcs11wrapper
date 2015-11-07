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

import iaik.pkcs.pkcs11.wrapper.Constants;

/**
 * This class is a simeple implementation of InitializeArgs.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class DefaultInitializeArgs implements InitializeArgs {

  /**
   * The mutex-handler of this object.
   */
  protected MutexHandler mutexHandler_;

  /**
   * Indicates that application threads which are executing calls to the library may not use native
   * operating system calls to spawn new threads.
   */
  protected boolean libraryCantCreateOsThreads_;

  /**
   * Indicates that the libary may use mechanisms of the operating-system to do thread-locking.
   */
  protected boolean osLockingOk_;

  /**
   * The reserved parameter in the initialization arguments.
   */
  protected Object reserved_;

  /**
   * Default constructor.
   * 
   * @postconditions (mutexHandler_ == null) and (libraryCantCreateOsThreads_ == false) and
   *                 (osLockingOk_ == true)
   */
  public DefaultInitializeArgs() {
    mutexHandler_ = null;
    libraryCantCreateOsThreads_ = false;
    osLockingOk_ = true;
    reserved_ = null;
  }

  /**
   * Constructor, taking a mutex-handler, the libraryCantCreateOsThreads flag and the osLockingOk
   * flag.
   * 
   * @param mutexHandler
   *          The PKCS#11 module should use this mutex-handler.
   * @param libraryCantCreateOsThreads
   *          Indicates that application threads which are executing calls to the library may not
   *          use native operating system calls to spawn new threads .
   * @param osLockingOk
   *          Indicates that the libary may use mechanisms of the operating-system to do
   *          thread-locking.
   * 
   * @postconditions (mutexHandler_ == mutexHandler) and (libraryCantCreateOsThreads_ ==
   *                 libraryCantCreateOsThreads) and (osLockingOk_ == osLockingOk)
   */
  public DefaultInitializeArgs(MutexHandler mutexHandler,
      boolean libraryCantCreateOsThreads, boolean osLockingOk) {
    mutexHandler_ = mutexHandler;
    libraryCantCreateOsThreads_ = libraryCantCreateOsThreads;
    osLockingOk_ = osLockingOk;
    reserved_ = null;
  }

  /**
   * This method returns the object that implements the functionality for handling mutexes. It
   * returns null, if no handler is set. If this method returns null, the wrapper does not pass any
   * callback functions to the underlying module; i.e. is passes null-pointer for the functions.
   * 
   * @return The handler object for mutex functionality, or null, if there is no handler for
   *         mutexes.
   * 
   * @postconditions (result == mutexHandler_)
   */
  public MutexHandler getMutexHandler() {
    return mutexHandler_;
  }

  /**
   * Check, if application threads which are executing calls to the library may not use native
   * operating system calls to spawn new threads.
   * 
   * @return True, if application threads which are executing calls to the library may not use
   *         native operating system calls to spawn new threads. False, if they may.
   * 
   * @postconditions (result == libraryCantCreateOsThreads_)
   */
  public boolean isLibraryCantCreateOsThreads() {
    return libraryCantCreateOsThreads_;
  }

  /**
   * Check, if the library can use the native operation system threading model for locking.
   * 
   * @return True, if the library can use the native operation system threading model for locking.
   *         Fasle, otherwise.
   * 
   * @postconditions (result == osLockingOk_)
   */
  public boolean isOsLockingOk() {
    return osLockingOk_;
  }

  /**
   * Reserved parameter.
   * 
   * @return Should be null in this version.
   */
  public Object getReserved() {
    return reserved_;
  }

  /**
   * This method sets the object that implements the functionality for handling mutexes. It should
   * be null to set no handler.
   * 
   * @param mutexHandler
   *          The handler object for mutex functionality, or null to use no handler.
   * 
   * @postconditions (mutexHandler_ = mutexHandler)
   */
  public void setMutexHandler(MutexHandler mutexHandler) {
    mutexHandler_ = mutexHandler;
  }

  /**
   * Set, if application threads which are executing calls to the library may not use native
   * operating system calls to spawn new threads.
   * 
   * @param libraryCantCreateOsThreads
   *          True, if application threads which are executing calls to the library may not use
   *          native operating system calls to spawn new threads. False, if they may.
   * 
   * @postconditions (libraryCantCreateOsThreads_ == libraryCantCreateOsThreads)
   */
  public void setLibraryCantCreateOsThreads(boolean libraryCantCreateOsThreads) {
    libraryCantCreateOsThreads_ = libraryCantCreateOsThreads;
  }

  /**
   * set, if the library can use the native operation system threading model for locking.
   * 
   * @param osLockingOk
   *          True, if the library can use the native operation system threading model for locking.
   *          Fasle, otherwise.
   * 
   * @postconditions (osLockingOk_ == osLockingOk)
   */
  public void setOsLockingOk(boolean osLockingOk) {
    osLockingOk_ = osLockingOk;
  }

  /**
   * Set the reserved parameter.
   * 
   * @param reserved
   *          Should be null in this version.
   */
  public void setReserved(Object reserved) {
    reserved_ = reserved;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return The string representation of object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Mutex Handler: ");
    buffer.append((mutexHandler_ != null) ? "present" : "not present");
    buffer.append(Constants.NEWLINE);

    buffer.append("Library can't create OS-Threads: ");
    buffer.append(libraryCantCreateOsThreads_);
    buffer.append(Constants.NEWLINE);

    buffer.append("OS-Locking OK: ");
    buffer.append(osLockingOk_);
    buffer.append(Constants.NEWLINE);

    buffer.append("The reserved parameter is: ");
    buffer.append((reserved_ != null) ? reserved_.toString() : "null");

    return buffer.toString();
  }

}
