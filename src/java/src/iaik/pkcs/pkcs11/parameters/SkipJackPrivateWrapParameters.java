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
import iaik.pkcs.pkcs11.wrapper.CK_SKIPJACK_PRIVATE_WRAP_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the Mechanism.SKIPJACK_PRIVATE_WRAP.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (password_ <> null) and (publicData_ <> null) and (randomA_ <> null) and (primeP_ <>
 *             null) and (baseG_ <> null) and (subprimeQ_ <> null)
 */
public class SkipJackPrivateWrapParameters implements Parameters {

  /**
   * The user-supplied password.
   */
  protected byte[] password_;

  /**
   * The other party's key exchange public key value.
   */
  protected byte[] publicData_;

  /**
   * The random Ra data.
   */
  protected byte[] randomA_;

  /**
   * The prime p value.
   */
  protected byte[] primeP_;

  /**
   * The base g value.
   */
  protected byte[] baseG_;

  /**
   * The subprime q value.
   */
  protected byte[] subprimeQ_;

  /**
   * Create a new SkipJackPrivateWrapParameters object with the given attributes.
   * 
   * @param password
   *          The user-supplied password.
   * @param publicData
   *          The other party's key exchange public key value.
   * @param randomA
   *          The random Ra data.
   * @param primeP
   *          The prime p value.
   * @param baseG
   *          The base g value.
   * @param subprimeQ
   *          The subprime q value.
   * @preconditions (password <> null) and (publicData <> null) and (randomA <> null) and (primeP <>
   *                null) and (baseG <> null) and (subprimeQ <> null)
   * 
   */
  public SkipJackPrivateWrapParameters(byte[] password, byte[] publicData,
      byte[] randomA, byte[] primeP, byte[] baseG, byte[] subprimeQ) {
    if (password == null) {
      throw new NullPointerException("Argument \"password\" must not be null.");
    }
    if (publicData == null) {
      throw new NullPointerException("Argument \"publicData\" must not be null.");
    }
    if (randomA == null) {
      throw new NullPointerException("Argument \"randomA\" must not be null.");
    }
    if (primeP == null) {
      throw new NullPointerException("Argument \"primeP\" must not be null.");
    }
    if (baseG == null) {
      throw new NullPointerException("Argument \"baseG\" must not be null.");
    }
    if (subprimeQ == null) {
      throw new NullPointerException("Argument \"subprimeQ\" must not be null.");
    }
    password_ = password;
    publicData_ = publicData;
    randomA_ = randomA;
    primeP_ = primeP;
    baseG_ = baseG;
    subprimeQ_ = subprimeQ;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof SkipJackPrivateWrapParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    SkipJackPrivateWrapParameters clone;

    try {
      clone = (SkipJackPrivateWrapParameters) super.clone();

      clone.password_ = (byte[]) this.password_.clone();
      clone.publicData_ = (byte[]) this.publicData_.clone();
      clone.randomA_ = (byte[]) this.randomA_.clone();
      clone.primeP_ = (byte[]) this.primeP_.clone();
      clone.baseG_ = (byte[]) this.baseG_.clone();
      clone.subprimeQ_ = (byte[]) this.subprimeQ_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_SKIPJACK_PRIVATE_WRAP_PARAMS class.
   * 
   * @return This object as a CK_SKIPJACK_PRIVATE_WRAP_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_SKIPJACK_PRIVATE_WRAP_PARAMS params = new CK_SKIPJACK_PRIVATE_WRAP_PARAMS();

    params.pPassword = password_;
    params.pPublicData = publicData_;
    params.pRandomA = randomA_;
    params.pPrimeP = primeP_;
    params.pBaseG = baseG_;
    params.pSubprimeQ = subprimeQ_;

    return params;
  }

  /**
   * Get the user-supplied password.
   * 
   * @return The user-supplied password.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPassword() {
    return password_;
  }

  /**
   * Get the other party's key exchange public key value.
   * 
   * @return The other party's key exchange public key value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPublicData() {
    return publicData_;
  }

  /**
   * Get the random Ra data.
   * 
   * @return The random Ra data.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getRandomA() {
    return randomA_;
  }

  /**
   * Get the prime p value.
   * 
   * @return The prime p value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPrimeP() {
    return primeP_;
  }

  /**
   * Get the base g value.
   * 
   * @return The base g value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getBaseG() {
    return baseG_;
  }

  /**
   * Get the subprime q value.
   * 
   * @return The subprime q value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getSubprimeQ() {
    return subprimeQ_;
  }

  /**
   * Set the user-supplied password.
   * 
   * @param password
   *          The user-supplied password.
   * @preconditions (password <> null)
   * 
   */
  public void setPassword(byte[] password) {
    if (password == null) {
      throw new NullPointerException("Argument \"password\" must not be null.");
    }
    password_ = password;
  }

  /**
   * Set the other party's key exchange public key value.
   * 
   * @param publicData
   *          The other party's key exchange public key value.
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
   * Set the random Ra data.
   * 
   * @param randomA
   *          The random Ra data.
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
   * Set the prime p value.
   * 
   * @param primeP
   *          The prime p value.
   * @preconditions (primeP <> null)
   * 
   */
  public void setPrimeP(byte[] primeP) {
    if (primeP == null) {
      throw new NullPointerException("Argument \"primeP\" must not be null.");
    }
    primeP_ = primeP;
  }

  /**
   * Set the base g value.
   * 
   * @param baseG
   *          The base g value.
   * @preconditions (baseG <> null)
   * 
   */
  public void setBaseG(byte[] baseG) {
    if (baseG == null) {
      throw new NullPointerException("Argument \"baseG\" must not be null.");
    }
    baseG_ = baseG;
  }

  /**
   * Set the subprime q value.
   * 
   * @param subprimeQ
   *          The subprime q value.
   * @preconditions (subprimeQ <> null)
   * 
   */
  public void setSubprimeQ(byte[] subprimeQ) {
    if (subprimeQ == null) {
      throw new NullPointerException("Argument \"subprimeQ\" must not be null.");
    }
    subprimeQ_ = subprimeQ;
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
    buffer.append("Passord (hex): ");
    buffer.append(Functions.toHexString(password_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Public Data (hex): ");
    buffer.append(Functions.toHexString(publicData_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Random Data A (hex): ");
    buffer.append(Functions.toHexString(randomA_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Prime P (hex): ");
    buffer.append(Functions.toHexString(primeP_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Base G (hex): ");
    buffer.append(Functions.toHexString(baseG_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Subprime Q (hex): ");
    buffer.append(Functions.toHexString(subprimeQ_));
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

    if (otherObject instanceof SkipJackPrivateWrapParameters) {
      SkipJackPrivateWrapParameters other = (SkipJackPrivateWrapParameters) otherObject;
      equal = (this == other)
          || (Functions.equals(this.password_, other.password_)
              && Functions.equals(this.publicData_, other.publicData_)
              && Functions.equals(this.randomA_, other.randomA_)
              && Functions.equals(this.primeP_, other.primeP_)
              && Functions.equals(this.baseG_, other.baseG_) && Functions.equals(
              this.subprimeQ_, other.subprimeQ_));
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
    return Functions.hashCode(password_) ^ Functions.hashCode(publicData_)
        ^ Functions.hashCode(randomA_) ^ Functions.hashCode(primeP_)
        ^ Functions.hashCode(baseG_) ^ Functions.hashCode(subprimeQ_);
  }

}
