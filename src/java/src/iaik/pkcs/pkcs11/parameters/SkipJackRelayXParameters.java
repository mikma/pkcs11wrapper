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

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.wrapper.CK_SKIPJACK_RELAYX_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the Mechanism.SKIPJACK_RELAYX.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (oldWrappedX_ <> null) and (oldPassword_ <> null) and (oldPublicData_ <> null) and
 *             (oldRandomA_ <> null) and (newPassword_ <> null) and (newPublicData_ <> null) and
 *             (newRandomA_ <> null)
 */
public class SkipJackRelayXParameters implements Parameters {

  /**
   * The old wrapped key.
   */
  protected byte[] oldWrappedX_;

  /**
   * The old user-supplied password.
   */
  protected byte[] oldPassword_;

  /**
   * The old key exchange public key value.
   */
  protected byte[] oldPublicData_;

  /**
   * The old random Ra data.
   */
  protected byte[] oldRandomA_;

  /**
   * The new user-supplied password.
   */
  protected byte[] newPassword_;

  /**
   * The new key exchange public key value.
   */
  protected byte[] newPublicData_;

  /**
   * The new random Ra data.
   */
  protected byte[] newRandomA_;

  /**
   * Create a new SkipJackRelayXParameters object with the given attributes.
   * 
   * @param oldWrappedX
   *          The old wrapped key.
   * @param oldPassword
   *          The old user-supplied password.
   * @param oldPublicData
   *          The old key exchange public key value.
   * @param oldRandomA
   *          The old random Ra data.
   * @param newPassword
   *          The new user-supplied password.
   * @param newPublicData
   *          The new key exchange public key value.
   * @param newRandomA
   *          The new random Ra data.
   * @preconditions (oldWrappedX <> null) and (oldPassword <> null) and (oldPublicData <> null) and
   *                (oldRandomA <> null) and (newPassword <> null) and (newPublicData <> null) and
   *                (newRandomA <> null)
   * 
   */
  public SkipJackRelayXParameters(byte[] oldWrappedX, byte[] oldPassword,
      byte[] oldPublicData, byte[] oldRandomA, byte[] newPassword, byte[] newPublicData,
      byte[] newRandomA) {
    if (oldWrappedX == null) {
      throw new NullPointerException("Argument \"oldWrappedX\" must not be null.");
    }
    if (oldPassword == null) {
      throw new NullPointerException("Argument \"oldPassword\" must not be null.");
    }
    if (oldPublicData == null) {
      throw new NullPointerException("Argument \"oldPublicData\" must not be null.");
    }
    if (oldRandomA == null) {
      throw new NullPointerException("Argument \"oldRandomA\" must not be null.");
    }
    if (newPassword == null) {
      throw new NullPointerException("Argument \"newPassword\" must not be null.");
    }
    if (newPublicData == null) {
      throw new NullPointerException("Argument \"newPublicData\" must not be null.");
    }
    if (newRandomA == null) {
      throw new NullPointerException("Argument \"newRandomA\" must not be null.");
    }
    oldWrappedX_ = oldWrappedX;
    oldPassword_ = oldPassword;
    oldPublicData_ = oldPublicData;
    oldRandomA_ = oldRandomA;
    newPassword_ = newPassword;
    newPublicData_ = newPublicData;
    newRandomA_ = newRandomA;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof SkipJackRelayXParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    SkipJackRelayXParameters clone;

    try {
      clone = (SkipJackRelayXParameters) super.clone();

      clone.oldWrappedX_ = (byte[]) this.oldWrappedX_.clone();
      clone.oldPassword_ = (byte[]) this.oldPassword_.clone();
      clone.oldPublicData_ = (byte[]) this.oldPublicData_.clone();
      clone.oldRandomA_ = (byte[]) this.oldRandomA_.clone();
      clone.newPassword_ = (byte[]) this.newPassword_.clone();
      clone.newPublicData_ = (byte[]) this.newPublicData_.clone();
      clone.newRandomA_ = (byte[]) this.newRandomA_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_SKIPJACK_RELAYX_PARAMS class.
   * 
   * @return This object as a CK_SKIPJACK_RELAYX_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_SKIPJACK_RELAYX_PARAMS params = new CK_SKIPJACK_RELAYX_PARAMS();

    params.pOldWrappedX = oldWrappedX_;
    params.pOldPassword = oldPassword_;
    params.pOldPublicData = oldPublicData_;
    params.pOldRandomA = oldRandomA_;
    params.pNewPassword = newPassword_;
    params.pNewPublicData = newPublicData_;
    params.pNewRandomA = newRandomA_;

    return params;
  }

  /**
   * Get the old wrapped key.
   * 
   * @return The old wrapped key.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getOldWrappedX() {
    return oldWrappedX_;
  }

  /**
   * Get the old user-supplied password.
   * 
   * @return The old user-supplied password.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getOldPassword() {
    return oldPassword_;
  }

  /**
   * Get the old other party's key exchange public key value.
   * 
   * @return The old other party's key exchange public key value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getOldPublicData() {
    return oldPublicData_;
  }

  /**
   * Get the old random Ra data.
   * 
   * @return The old random Ra data.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getOldRandomA() {
    return oldRandomA_;
  }

  /**
   * Get the new user-supplied password.
   * 
   * @return The new user-supplied password.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getNewPassword() {
    return newPassword_;
  }

  /**
   * Get the new other party's key exchange public key value.
   * 
   * @return The new other party's key exchange public key value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getNewPublicData() {
    return newPublicData_;
  }

  /**
   * Get the new random Ra data.
   * 
   * @return The new random Ra data.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getNewRandomA() {
    return newRandomA_;
  }

  /**
   * Set the old wrapped key.
   * 
   * @param oldWrappedX
   *          The old wrapped key.
   * @preconditions (oldWrappedX <> null)
   * 
   */
  public void setOldWrappedX(byte[] oldWrappedX) {
    if (oldWrappedX == null) {
      throw new NullPointerException("Argument \"oldWrappedX\" must not be null.");
    }
    oldWrappedX_ = oldWrappedX;
  }

  /**
   * Set the old user-supplied password.
   * 
   * @param oldPassword
   *          The old user-supplied password.
   * @preconditions (oldPassword <> null)
   * 
   */
  public void setOldPassword(byte[] oldPassword) {
    if (oldPassword == null) {
      throw new NullPointerException("Argument \"oldPassword\" must not be null.");
    }
    oldPassword_ = oldPassword;
  }

  /**
   * Set the old other party's key exchange public key value.
   * 
   * @param oldPublicData
   *          The old other party's key exchange public key value.
   * @preconditions (oldPublicData <> null)
   * 
   */
  public void setOldPublicData(byte[] oldPublicData) {
    if (oldPublicData == null) {
      throw new NullPointerException("Argument \"oldPublicData\" must not be null.");
    }
    oldPublicData_ = oldPublicData;
  }

  /**
   * Set the old random Ra data.
   * 
   * @param oldRandomA
   *          The old random Ra data.
   * @preconditions (oldRandomA <> null)
   * 
   */
  public void setOldRandomA(byte[] oldRandomA) {
    if (oldRandomA == null) {
      throw new NullPointerException("Argument \"oldRandomA\" must not be null.");
    }
    oldRandomA_ = oldRandomA;
  }

  /**
   * Set the new user-supplied password.
   * 
   * @param newPassword
   *          The new user-supplied password.
   * @preconditions (newPassword <> null)
   * 
   */
  public void setNewPassword(byte[] newPassword) {
    if (newPassword == null) {
      throw new NullPointerException("Argument \"newPassword\" must not be null.");
    }
    newPassword_ = newPassword;
  }

  /**
   * Set the new other party's key exchange public key value.
   * 
   * @param newPublicData
   *          The new other party's key exchange public key value.
   * @preconditions (oldPublicData <> null)
   * 
   */
  public void setNewPublicData(byte[] newPublicData) {
    if (newPublicData == null) {
      throw new NullPointerException("Argument \"newPublicData\" must not be null.");
    }
    newPublicData_ = newPublicData;
  }

  /**
   * Set the new random Ra data.
   * 
   * @param newRandomA
   *          The new random Ra data.
   * @preconditions (newRandomA <> null)
   * 
   */
  public void setNewRandomA(byte[] newRandomA) {
    if (newRandomA == null) {
      throw new NullPointerException("Argument \"newRandomA\" must not be null.");
    }
    newRandomA_ = newRandomA;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   * 
   * @return A string representation of this object.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(Constants.INDENT);
    buffer.append("Old Wrapped Key (hex): ");
    buffer.append(Functions.toHexString(oldWrappedX_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Old Passord (hex): ");
    buffer.append(Functions.toHexString(oldPassword_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Old Public Data (hex): ");
    buffer.append(Functions.toHexString(oldPublicData_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Old Random Data A (hex): ");
    buffer.append(Functions.toHexString(oldRandomA_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("New Passord (hex): ");
    buffer.append(Functions.toHexString(newPassword_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("New Public Data (hex): ");
    buffer.append(Functions.toHexString(newPublicData_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("New Random Data A (hex): ");
    buffer.append(Functions.toHexString(newRandomA_));
    // buffer.append(Constants.NEWLINE);

    return buffer.toString();
  }

  /**
   * Compares all member variables of this object with the other object. Returns only true, if all
   * are equal in both objects.
   * 
   * @param otherObject
   *          The other object to compare to.
   * @return True, if other is an instance of this class and all member variables of both objects
   *         are equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof SkipJackRelayXParameters) {
      SkipJackRelayXParameters other = (SkipJackRelayXParameters) otherObject;
      equal = (this == other)
          || (Functions.equals(this.oldWrappedX_, other.oldWrappedX_)
              && Functions.equals(this.oldPassword_, other.oldPassword_)
              && Functions.equals(this.oldPublicData_, other.oldPublicData_)
              && Functions.equals(this.oldRandomA_, other.oldRandomA_)
              && Functions.equals(this.newPassword_, other.newPassword_)
              && Functions.equals(this.newPublicData_, other.newPublicData_) && Functions
                .equals(this.newRandomA_, other.newRandomA_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return Functions.hashCode(oldWrappedX_) ^ Functions.hashCode(oldPassword_)
        ^ Functions.hashCode(oldPublicData_) ^ Functions.hashCode(oldRandomA_)
        ^ Functions.hashCode(newPassword_) ^ Functions.hashCode(newPublicData_)
        ^ Functions.hashCode(newRandomA_);
  }

}
