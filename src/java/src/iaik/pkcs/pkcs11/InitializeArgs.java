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

/**
 * The interface that an object must implement to be a valid parameter for the initialize method of
 * a Module object.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public interface InitializeArgs {

  /**
   * This method returns the object that implements the functionality for handling mutexes. It
   * returns null, if no handler is set. If this method returns null, the wrapper does not pass any
   * callback functions to the underlying module; i.e. is passes null-pointer for the functions.
   * 
   * @return The handler object for mutex functionality, or null, if there is no handler for
   *         mutexes.
   */
  public MutexHandler getMutexHandler();

  /**
   * Check, if application threads which are executing calls to the library may not use native
   * operating system calls to spawn new threads.
   * 
   * @return True, if application threads which are executing calls to the library may not use
   *         native operating system calls to spawn new threads. False, if they may.
   */
  public boolean isLibraryCantCreateOsThreads();

  /**
   * Check, if the library can use the native operation system threading model for locking.
   * 
   * @return True, if the library can use the native operation system threading model for locking.
   *         Fasle, otherwise.
   */
  public boolean isOsLockingOk();

  /**
   * Reserved parameter.
   * 
   * @return Should be null in this version.
   * 
   * @postconditions (result == null)
   */
  public Object getReserved();

}
