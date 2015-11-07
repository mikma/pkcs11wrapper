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
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This abstract class encapsulates parameters for the DH mechanisms Mechanism.ECDH1_DERIVE,
 * Mechanism.ECDH1_COFACTOR_DERIVE, Mechanism.ECMQV_DERIVE, Mechanism.X9_42_DH_DERIVE ,
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (keyDerivationFunction_ == KeyDerivationFunctionType.NULL) or (keyDerivationFunction_
 *             == KeyDerivationFunctionType.SHA1_KDF) or (keyDerivationFunction_ ==
 *             KeyDerivationFunctionType.SHA1_KDF_ASN1) or (keyDerivationFunction_ ==
 *             KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) and (publicData_ <> null)
 */
abstract public class DHKeyDerivationParameters implements Parameters {

  /**
   * This interface defines the available key derivation function types as defined by PKCS#11:
   * CKD_NULL, CKD_SHA1_KDF, CKD_SHA1_KDF_ASN1, CKD_SHA1_KDF_CONCATENATE.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface KeyDerivationFunctionType {

    /**
     * The indentifier for CKD_NULL.
     */
    static public final long NULL = PKCS11Constants.CKD_NULL;

    /**
     * The indentifier for CKD_SHA1_KDF.
     */
    static public final long SHA1_KDF = PKCS11Constants.CKD_SHA1_KDF;

    /**
     * The indentifier for CKD_SHA1_KDF_ASN1.
     */
    static public final long SHA1_KDF_ASN1 = PKCS11Constants.CKD_SHA1_KDF_ASN1;

    /**
     * The indentifier for CKD_SHA1_KDF_CONCATENATE.
     */
    static public final long SHA1_KDF_CONCATENATE = PKCS11Constants.CKD_SHA1_KDF_CONCATENATE;

  }

  /**
   * The key derivation function used on the shared secret value.
   */
  protected long keyDerivationFunction_;

  /**
   * The other partie's public key value.
   */
  protected byte[] publicData_;

  /**
   * Create a new DHKeyDerivationParameters object with the given attributes.
   * 
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value. One of the values defined
   *          in KeyDerivationFunctionType.
   * @param publicData
   *          The other partie's public key value.
   * @preconditions ((keyDerivationFunction == KeyDerivationFunctionType.NULL) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF_ASN1) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) and
   *                (publicData <> null)
   * 
   */
  protected DHKeyDerivationParameters(long keyDerivationFunction, byte[] publicData) {
    if ((keyDerivationFunction != KeyDerivationFunctionType.NULL)
        && (keyDerivationFunction != KeyDerivationFunctionType.SHA1_KDF)
        && (keyDerivationFunction != KeyDerivationFunctionType.SHA1_KDF_ASN1)
        && (keyDerivationFunction != KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) {
      throw new IllegalArgumentException(
          "Illegal value for argument\"keyDerivationFunction\": "
              + Functions.toHexString(keyDerivationFunction));
    }
    if (publicData == null) {
      throw new NullPointerException("Argument \"publicData\" must not be null.");
    }
    keyDerivationFunction_ = keyDerivationFunction;
    publicData_ = publicData;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof DHKeyDerivationParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    DHKeyDerivationParameters clone;

    try {
      clone = (DHKeyDerivationParameters) super.clone();

      clone.publicData_ = (byte[]) this.publicData_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get the key derivation function used on the shared secret value.
   * 
   * @return The key derivation function used on the shared secret value. One of the values defined
   *         in KeyDerivationFunctionType.
   */
  public long getKeyDerivationFunction() {
    return keyDerivationFunction_;
  }

  /**
   * Get the other partie's public key value.
   * 
   * @return The other partie's public key value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPublicData() {
    return publicData_;
  }

  /**
   * Set the ey derivation function used on the shared secret value.
   * 
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value. One of the values defined
   *          in KeyDerivationFunctionType.
   * @preconditions (keyDerivationFunction == KeyDerivationFunctionType.NULL) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF)) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF_ASN1)) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE))
   * 
   */
  public void setKeyDerivationFunction(long keyDerivationFunction) {
    if ((keyDerivationFunction != KeyDerivationFunctionType.NULL)
        && (keyDerivationFunction != KeyDerivationFunctionType.SHA1_KDF)
        && (keyDerivationFunction != KeyDerivationFunctionType.SHA1_KDF_ASN1)
        && (keyDerivationFunction != KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) {
      throw new IllegalArgumentException(
          "Illegal value for argument\"keyDerivationFunction\": "
              + Functions.toHexString(keyDerivationFunction));
    }
    keyDerivationFunction_ = keyDerivationFunction;
  }

  /**
   * Set the other partie's public key value.
   * 
   * @param publicData
   *          The other partie's public key value.
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
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   * 
   * @return A string representation of this object.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(Constants.INDENT);
    buffer.append("Key Derivation Function: ");
    if (keyDerivationFunction_ == KeyDerivationFunctionType.NULL) {
      buffer.append("NULL");
    } else if (keyDerivationFunction_ == KeyDerivationFunctionType.SHA1_KDF) {
      buffer.append("SHA1_KDF");
    } else if (keyDerivationFunction_ == KeyDerivationFunctionType.SHA1_KDF_ASN1) {
      buffer.append("SHA1_KDF_ASN1");
    } else if (keyDerivationFunction_ == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE) {
      buffer.append("SHA1_KDF_CONCATENATE");
    } else {
      buffer.append("<unknown>");
    }
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Public Data: ");
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

    if (otherObject instanceof DHKeyDerivationParameters) {
      DHKeyDerivationParameters other = (DHKeyDerivationParameters) otherObject;
      equal = (this == other)
          || ((this.keyDerivationFunction_ == other.keyDerivationFunction_) && Functions
              .equals(this.publicData_, other.publicData_));
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
    return ((int) keyDerivationFunction_) ^ Functions.hashCode(publicData_);
  }

}
