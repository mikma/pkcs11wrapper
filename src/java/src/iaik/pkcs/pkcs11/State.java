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

/**
 * Objects of this class show the state of a session. This state is only a snapshot of the session's
 * state at the time this state object was created.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class State implements Cloneable {

  /**
   * Constant for a read-only public session.
   */
  public final static State RO_PUBLIC_SESSION = new State(
      PKCS11Constants.CKS_RO_PUBLIC_SESSION);

  /**
   * Constant for a read-only user session.
   */
  public final static State RO_USER_FUNCTIONS = new State(
      PKCS11Constants.CKS_RO_USER_FUNCTIONS);

  /**
   * Constant for a read-write public session.
   */
  public final static State RW_PUBLIC_SESSION = new State(
      PKCS11Constants.CKS_RW_PUBLIC_SESSION);

  /**
   * Constant for a read-write user session.
   */
  public final static State RW_USER_FUNCTIONS = new State(
      PKCS11Constants.CKS_RW_USER_FUNCTIONS);

  /**
   * Constant for a read-write security officer session.
   */
  public final static State RW_SO_FUNCTIONS = new State(
      PKCS11Constants.CKS_RW_SO_FUNCTIONS);

  /**
   * The status code of this state as defined in PKCS#11.
   */
  protected long code_;

  /**
   * Constructor that simply takes the status code as defined in PKCS#11.
   * 
   * @param code
   *          One of: PKCS11Constants.CKS_RO_PUBLIC_SESSION, PKCS11Constants.CKS_RO_USER_FUNCTIONS,
   *          PKCS11Constants.CKS_RW_PUBLIC_SESSION, PKCS11Constants.CKS_RW_USER_FUNCTIONS or
   *          PKCS11Constants.CKS_RW_SO_FUNCTIONS.
   * 
   */
  protected State(long code) {
    code_ = code;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof State) and (result.equals(this))
   */
  public java.lang.Object clone() {
    State clone;

    try {
      clone = (State) super.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Compares the state code of this object with the other object. Returns only true, if those are
   * equal in both objects.
   * 
   * @param otherObject
   *          The other State object.
   * @return True, if other is an instance of State and the state code of both objects are equal.
   *         False, otherwise.
   */
  public boolean equals(Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof State) {
      State other = (State) otherObject;
      equal = (this == other) || (this.code_ == other.code_);
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the state code.
   */
  public int hashCode() {
    return (int) code_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return The string representation of object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    String name;
    if (code_ == PKCS11Constants.CKS_RO_PUBLIC_SESSION) {
      name = "Read-Only Public Session";
    } else if (code_ == PKCS11Constants.CKS_RO_USER_FUNCTIONS) {
      name = "Read-Only User Session";
    } else if (code_ == PKCS11Constants.CKS_RW_PUBLIC_SESSION) {
      name = "Read/Write Public Session";
    } else if (code_ == PKCS11Constants.CKS_RW_USER_FUNCTIONS) {
      name = "Read/Write User Functions";
    } else if (code_ == PKCS11Constants.CKS_RW_SO_FUNCTIONS) {
      name = "Read/Write Security Officer Functions";
    } else {
      name = "ERROR: unknown session state with code: " + code_;
    }

    buffer.append(name);

    return buffer.toString();
  }

}
