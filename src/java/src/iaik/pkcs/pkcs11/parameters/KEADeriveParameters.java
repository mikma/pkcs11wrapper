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
import iaik.pkcs.pkcs11.wrapper.CK_KEA_DERIVE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the Mechanism.KEA_KEY_DERIVE.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (randomA_ <> null) and (randomB_ <> null) and (publicData_ <> null)
 */
public class KEADeriveParameters implements Parameters {

  /**
   * Option for generating the key (called a TEK). The value is TRUE if the sender (originator)
   * generates the TEK, FALSE if the recipient is regenerating the TEK.
   */
  protected boolean isSender_;

  /**
   * The Ra data.
   */
  protected byte[] randomA_;

  /**
   * The Rb data.
   */
  protected byte[] randomB_;

  /**
   * The other party's KEA public key value.
   */
  protected byte[] publicData_;

  /**
   * Create a new KEADeriveParameters object with the given attributes.
   * 
   * @param isSender
   *          Option for generating the key (called a TEK). The value is TRUE if the sender
   *          (originator) generates the TEK, FALSE if the recipient is regenerating the TEK.
   * @param randomA
   *          The random data Ra.
   * @param randomB
   *          The random data Rb.
   * @param publicData
   *          The other party's KEA public key value.
   * @preconditions (randomA <> null) and (randomB <> null) and (publicData <> null)
   * 
   */
  public KEADeriveParameters(boolean isSender, byte[] randomA, byte[] randomB,
      byte[] publicData) {
    if (randomA == null) {
      throw new NullPointerException("Argument \"randomA\" must not be null.");
    }
    if (randomB == null) {
      throw new NullPointerException("Argument \"randomB\" must not be null.");
    }
    if (publicData == null) {
      throw new NullPointerException("Argument \"publicData\" must not be null.");
    }
    isSender_ = isSender;
    randomA_ = randomA;
    randomB_ = randomB;
    publicData_ = publicData;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof KEADeriveParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    KEADeriveParameters clone;

    try {
      clone = (KEADeriveParameters) super.clone();

      clone.randomA_ = (byte[]) this.randomA_.clone();
      clone.randomB_ = (byte[]) this.randomB_.clone();
      clone.publicData_ = (byte[]) this.publicData_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_KEA_DERIVE_PARAMS class.
   * 
   * @return This object as a CK_KEA_DERIVE_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_KEA_DERIVE_PARAMS params = new CK_KEA_DERIVE_PARAMS();

    params.isSender = isSender_;
    params.pRandomA = randomA_;
    params.pRandomB = randomB_;
    params.pPublicData = publicData_;

    return params;
  }

  /**
   * Get the other party's KEA public key value.
   * 
   * @return The other party's KEA public key value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPublicData() {
    return publicData_;
  }

  /**
   * Get the random data Ra.
   * 
   * @return The random data Ra.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getRandomA() {
    return randomA_;
  }

  /**
   * Get the random data Rb.
   * 
   * @return The random data Rb.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getRandomB() {
    return randomB_;
  }

  /**
   * Get the option for generating the key (called a TEK).
   * 
   * @return True if the sender (originator) generates the TEK, false if the recipient is
   *         regenerating the TEK.
   */
  public boolean isSender() {
    return isSender_;
  }

  /**
   * Set the other party's KEA public key value.
   * 
   * @param publicData
   *          The other party's KEA public key value.
   * @preconditions (publicData <> null)
   * 
   */
  public void setPublicData(byte[] publicData) {
    if (publicData == null) {
      throw new NullPointerException("Argument \"publicData\" must not be null.");
    }
    publicData_ = publicData;
  }

  /**
   * Set the random data Ra.
   * 
   * @param randomA
   *          The random data Ra.
   * @preconditions (randomA <> null)
   * 
   */
  public void setRandomA(byte[] randomA) {
    if (randomA == null) {
      throw new NullPointerException("Argument \"randomA\" must not be null.");
    }
    randomA_ = randomA;
  }

  /**
   * Set the random data Rb.
   * 
   * @param randomB
   *          The random data Rb.
   * @preconditions (randomB <> null)
   * 
   */
  public void setRandomB(byte[] randomB) {
    if (randomB == null) {
      throw new NullPointerException("Argument \"randomB\" must not be null.");
    }
    randomB_ = randomB;
  }

  /**
   * Set the option for generating the key (called a TEK).
   * 
   * @param isSender
   *          True if the sender (originator) generates the TEK, false if the recipient is
   *          regenerating the TEK.
   */
  public void setSender(boolean isSender) {
    isSender_ = isSender;
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
    buffer.append("Is Sender: ");
    buffer.append(isSender_);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Random Data A (hex): ");
    buffer.append(Functions.toHexString(randomA_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Random Data B (hex): ");
    buffer.append(Functions.toHexString(randomB_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Public Data (hex): ");
    buffer.append(Functions.toHexString(publicData_));
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

    if (otherObject instanceof KEADeriveParameters) {
      KEADeriveParameters other = (KEADeriveParameters) otherObject;
      equal = (this == other)
          || ((this.isSender_ == other.isSender_)
              && Functions.equals(this.randomA_, other.randomA_)
              && Functions.equals(this.randomB_, other.randomB_) && Functions.equals(
              this.publicData_, other.publicData_));
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
    return Functions.hashCode(randomA_) ^ Functions.hashCode(randomB_)
        ^ Functions.hashCode(publicData_);
  }

}
