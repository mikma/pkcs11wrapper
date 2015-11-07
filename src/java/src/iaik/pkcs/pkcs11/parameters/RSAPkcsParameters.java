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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This abstract class encapsulates parameters for the RSA PKCS mechanisms Mechanism.RSA_PKCS_OAEP
 * and Mechanism.RSA_PKCS_PSS.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (hashAlgorithm_ <> null) and (maskGenerationFunction_ ==
 *             MessageGenerationFunctionType.Sha1)
 */
abstract public class RSAPkcsParameters implements Parameters {

  /**
   * This interface defines the available message generation function types as defined by PKCS#11:
   * CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA384 and CKG_MGF1_SHA512.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface MessageGenerationFunctionType {

    /**
     * The indentifier for CKG_MGF1_SHA1.
     */
    static public final long SHA1 = PKCS11Constants.CKG_MGF1_SHA1;

    /**
     * The indentifier for CKG_MGF1_SHA256.
     */
    static public final long SHA256 = PKCS11Constants.CKG_MGF1_SHA256;

    /**
     * The indentifier for CKG_MGF1_SHA384.
     */
    static public final long SHA384 = PKCS11Constants.CKG_MGF1_SHA384;

    /**
     * The indentifier for CKG_MGF1_SHA512.
     */
    static public final long SHA512 = PKCS11Constants.CKG_MGF1_SHA512;

  }

  /**
   * The message digest algorithm used to calculate the digest of the encoding parameter.
   */
  protected Mechanism hashAlgorithm_;

  /**
   * The mask to apply to the encoded block.
   */
  protected long maskGenerationFunction_;

  /**
   * Create a new RSAPkcsarameters object with the given attributes.
   * 
   * @param hashAlgorithm
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @param maskGenerationFunction
   *          The mask to apply to the encoded block. One of the constants defined in the
   *          MessageGenerationFunctionType interface.
   * @preconditions (hashAlgorithm <> null) and (maskGenerationFunction ==
   *                MessageGenerationFunctionType.Sha1)
   * 
   */
  protected RSAPkcsParameters(Mechanism hashAlgorithm, long maskGenerationFunction) {
    if (hashAlgorithm == null) {
      throw new NullPointerException("Argument \"hashAlgorithm\" must not be null.");
    }
    if ((maskGenerationFunction != MessageGenerationFunctionType.SHA1)
        && (maskGenerationFunction != MessageGenerationFunctionType.SHA256)
        && (maskGenerationFunction != MessageGenerationFunctionType.SHA384)
        && (maskGenerationFunction != MessageGenerationFunctionType.SHA512)) {
      throw new IllegalArgumentException(
          "Illegal value for argument\"maskGenerationFunction\": "
              + Functions.toHexString(maskGenerationFunction));
    }
    hashAlgorithm_ = hashAlgorithm;
    maskGenerationFunction_ = maskGenerationFunction;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof RSAPkcsParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    RSAPkcsParameters clone;

    try {
      clone = (RSAPkcsParameters) super.clone();

      clone.hashAlgorithm_ = (Mechanism) this.hashAlgorithm_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get the message digest algorithm used to calculate the digest of the encoding parameter.
   * 
   * @return The message digest algorithm used to calculate the digest of the encoding parameter.
   * 
   * @postconditions (result <> null)
   */
  public Mechanism getHashAlgorithm() {
    return hashAlgorithm_;
  }

  /**
   * Get the mask to apply to the encoded block.
   * 
   * @return The mask to apply to the encoded block.
   */
  public long getMaskGenerationFunction() {
    return maskGenerationFunction_;
  }

  /**
   * Set the message digest algorithm used to calculate the digest of the encoding parameter.
   * 
   * @param hashAlgorithm
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @preconditions (hashAlgorithm <> null)
   * 
   */
  public void setHashAlgorithm(Mechanism hashAlgorithm) {
    if (hashAlgorithm == null) {
      throw new NullPointerException("Argument \"hashAlgorithm\" must not be null.");
    }
    hashAlgorithm_ = hashAlgorithm;
  }

  /**
   * Set the mask function to apply to the encoded block. One of the constants defined in the
   * MessageGenerationFunctionType interface.
   * 
   * @param maskGenerationFunction
   *          The mask to apply to the encoded block.
   * @preconditions (maskGenerationFunction == MessageGenerationFunctionType.Sha1)
   * 
   */
  public void setMaskGenerationFunction(long maskGenerationFunction) {
    if ((maskGenerationFunction != MessageGenerationFunctionType.SHA1)
        && (maskGenerationFunction != MessageGenerationFunctionType.SHA256)
        && (maskGenerationFunction != MessageGenerationFunctionType.SHA384)
        && (maskGenerationFunction != MessageGenerationFunctionType.SHA512)) {
      throw new IllegalArgumentException(
          "Illegal value for argument\"maskGenerationFunction\": "
              + Functions.toHexString(maskGenerationFunction));
    }
    maskGenerationFunction_ = maskGenerationFunction;
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
    buffer.append("Hash Algorithm: ");
    buffer.append(hashAlgorithm_.toString());
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Mask Generation Function: ");
    if (maskGenerationFunction_ == MessageGenerationFunctionType.SHA1) {
      buffer.append("SHA-1");
    } else if (maskGenerationFunction_ == MessageGenerationFunctionType.SHA256) {
      buffer.append("SHA-256");
    } else if (maskGenerationFunction_ == MessageGenerationFunctionType.SHA384) {
      buffer.append("SHA-384");
    } else if (maskGenerationFunction_ == MessageGenerationFunctionType.SHA512) {
      buffer.append("SHA-512");
    } else {
      buffer.append("<unknown>");
    }
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

    if (otherObject instanceof RSAPkcsParameters) {
      RSAPkcsParameters other = (RSAPkcsParameters) otherObject;
      equal = (this == other)
          || (this.hashAlgorithm_.equals(other.hashAlgorithm_) && (this.maskGenerationFunction_ == other.maskGenerationFunction_));
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
    return hashAlgorithm_.hashCode() ^ ((int) maskGenerationFunction_);
  }

}
