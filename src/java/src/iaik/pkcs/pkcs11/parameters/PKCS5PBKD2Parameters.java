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
import iaik.pkcs.pkcs11.wrapper.CK_PKCS5_PBKD2_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This class encapsulates parameters for the Mechanism.PKCS5_PKKD2 mechanism.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (saltSource_ == SaltSourceType.SaltSpecified) and (saltSourceData_ <> null) and
 *             (pseudoRandomFunction_ == PseudoRandomFunctionType.HMACSha1) and
 *             (pseudoRandomFunctionData_ <> null)
 */
public class PKCS5PBKD2Parameters implements Parameters {

  /**
   * This interface defines the available pseudo-random function types as defined by PKCS#11:
   * CKP_PKCS5_PBKD2_HMAC_SHA1.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface PseudoRandomFunctionType {

    /**
     * The indentifier for HMAC Sha-1 version.
     */
    static public final long HMAC_SHA1 = PKCS11Constants.CKP_PKCS5_PBKD2_HMAC_SHA1;

  }

  /**
   * This interface defines the available sources of the salt value as defined by PKCS#11:
   * CKZ_SALT_SPECIFIED.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface SaltSourceType {

    /**
     * The indentifier for specified salt.
     */
    static public final long SALT_SPECIFIED = PKCS11Constants.CKZ_SALT_SPECIFIED;

  }

  /**
   * The source of the salt value.
   */
  protected long saltSource_;

  /**
   * The data used as the input for the salt source.
   */
  protected byte[] saltSourceData_;

  /**
   * The number of iterations to perform when generating each block of random data.
   */
  protected long iterations_;

  /**
   * The pseudo-random function (PRF) to used to generate the key.
   */
  protected long pseudoRandomFunction_;

  /**
   * The data used as the input for PRF in addition to the salt value.
   */
  protected byte[] pseudoRandomFunctionData_;

  /**
   * Create a new PBEDeriveParameters object with the given attributes.
   * 
   * @param saltSource
   *          The source of the salt value. One of the constants defined in the SaltSourceType
   *          interface.
   * @param saltSourceData
   *          The data used as the input for the salt source.
   * @param iterations
   *          The number of iterations to perform when generating each block of random data.
   * @param pseudoRandomFunction
   *          The pseudo-random function (PRF) to used to generate the key. One of the constants
   *          defined in the PseudoRandomFunctionType interface.
   * @param pseudoRandomFunctionData
   *          The data used as the input for PRF in addition to the salt value.
   * @preconditions (saltSource == SaltSourceType.SaltSpecified) and (saltSourceData <> null) and
   *                (pseudoRandomFunction == PseudoRandomFunctionType.HMACSha1) and
   *                (pseudoRandomFunctionData <> null)
   * 
   */
  public PKCS5PBKD2Parameters(long saltSource, byte[] saltSourceData, long iterations,
      long pseudoRandomFunction, byte[] pseudoRandomFunctionData) {
    if (saltSource != SaltSourceType.SALT_SPECIFIED) {
      throw new IllegalArgumentException("Illegal value for argument\"saltSource\": "
          + Functions.toHexString(saltSource));
    }
    if (saltSourceData == null) {
      throw new NullPointerException("Argument \"saltSourceData\" must not be null.");
    }
    if (pseudoRandomFunction != PseudoRandomFunctionType.HMAC_SHA1) {
      throw new IllegalArgumentException(
          "Illegal value for argument\"pseudoRandomFunction\": "
              + Functions.toHexString(pseudoRandomFunction));
    }
    if (pseudoRandomFunctionData == null) {
      throw new NullPointerException(
          "Argument \"pseudoRandomFunctionData\" must not be null.");
    }
    saltSource_ = saltSource;
    saltSourceData_ = saltSourceData;
    iterations_ = iterations;
    pseudoRandomFunction_ = pseudoRandomFunction;
    pseudoRandomFunctionData_ = pseudoRandomFunctionData;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof PKCS5PBKD2Parameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    PKCS5PBKD2Parameters clone;

    try {
      clone = (PKCS5PBKD2Parameters) super.clone();

      clone.saltSourceData_ = (byte[]) this.saltSourceData_.clone();
      clone.pseudoRandomFunctionData_ = (byte[]) this.pseudoRandomFunctionData_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_PKCS5_PBKD2_PARAMS class.
   * 
   * @return This object as a CK_PKCS5_PBKD2_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_PKCS5_PBKD2_PARAMS params = new CK_PKCS5_PBKD2_PARAMS();

    params.saltSource = saltSource_;
    params.pSaltSourceData = saltSourceData_;
    params.iterations = iterations_;
    params.prf = pseudoRandomFunction_;
    params.pPrfData = pseudoRandomFunctionData_;

    return params;
  }

  /**
   * Get the source of the salt value.
   * 
   * @return The source of the salt value.
   * 
   * @postconditions (result == SaltSourceType.SaltSpecified)
   */
  public long getSaltSource() {
    return saltSource_;
  }

  /**
   * Get the data used as the input for the salt source.
   * 
   * @return data used as the input for the salt source.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getSaltSourceData() {
    return saltSourceData_;
  }

  /**
   * Get the number of iterations to perform when generating each block of random data.
   * 
   * @return The number of iterations to perform when generating each block of random data.
   */
  public long getIterations() {
    return iterations_;
  }

  /**
   * Get the pseudo-random function (PRF) to used to generate the key.
   * 
   * @return The pseudo-random function (PRF) to used to generate the key.
   * 
   * @postconditions (result == PseudoRandomFunctionType.HMACSha1)
   */
  public long getPseudoRandomFunction() {
    return pseudoRandomFunction_;
  }

  /**
   * Get the data used as the input for PRF in addition to the salt value.
   * 
   * @return The data used as the input for PRF in addition to the salt value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPseudoRandomFunctionData() {
    return pseudoRandomFunctionData_;
  }

  /**
   * Set the source of the salt value.
   * 
   * @param saltSource
   *          The source of the salt value. One of the constants defined in the SaltSourceType
   *          interface
   * @preconditions (saltSource == SaltSourceType.SaltSpecified)
   * 
   */
  public void setSaltSource(long saltSource) {
    if (saltSource != SaltSourceType.SALT_SPECIFIED) {
      throw new IllegalArgumentException("Illegal value for argument\"saltSource\": "
          + Functions.toHexString(saltSource));
    }
    saltSource_ = saltSource;
  }

  /**
   * Set the data used as the input for the salt source.
   * 
   * @param saltSourceData
   *          The data used as the input for the salt source.
   * @preconditions (saltSourceData <> null)
   * 
   */
  public void setSaltSourceData(byte[] saltSourceData) {
    if (saltSourceData == null) {
      throw new NullPointerException("Argument \"saltSourceData\" must not be null.");
    }
    saltSourceData_ = saltSourceData;
  }

  /**
   * Set the number of iterations to perform when generating each block of random data.
   * 
   * @param iterations
   *          The number of iterations to perform when generating each block of random data.
   */
  public void setIterations(long iterations) {
    iterations_ = iterations;
  }

  /**
   * Set the pseudo-random function (PRF) to used to generate the key.
   * 
   * @param pseudoRandomFunction
   *          The pseudo-random function (PRF) to used to generate the key. One of the constants
   *          defined in the PseudoRandomFunctionType interface.
   * @preconditions (pseudoRandomFunction == PseudoRandomFunctionType.HMACSha1)
   * 
   */
  public void setPseudoRandomFunction(long pseudoRandomFunction) {
    if (pseudoRandomFunction != PseudoRandomFunctionType.HMAC_SHA1) {
      throw new IllegalArgumentException(
          "Illegal value for argument\"pseudoRandomFunction\": "
              + Functions.toHexString(pseudoRandomFunction));
    }
    pseudoRandomFunction_ = pseudoRandomFunction;
  }

  /**
   * Set the data used as the input for PRF in addition to the salt value.
   * 
   * @param pseudoRandomFunctionData
   *          The data used as the input for PRF in addition to the salt value.
   * @preconditions (pseudoRandomFunctionData <> null)
   * 
   */
  public void setPseudoRandomFunctionData(byte[] pseudoRandomFunctionData) {
    if (pseudoRandomFunctionData == null) {
      throw new NullPointerException(
          "Argument \"pseudoRandomFunctionData\" must not be null.");
    }
    pseudoRandomFunctionData_ = pseudoRandomFunctionData;
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
    buffer.append("Salt Source: ");
    if (saltSource_ == SaltSourceType.SALT_SPECIFIED) {
      buffer.append("Salt Specified");
    } else {
      buffer.append("<unknown>");
    }
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Salt Source Data (hex): ");
    buffer.append(Functions.toHexString(saltSourceData_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Iterations (dec): ");
    buffer.append(iterations_);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Pseudo-Random Function: ");
    if (pseudoRandomFunction_ == PseudoRandomFunctionType.HMAC_SHA1) {
      buffer.append("HMAC SHA-1");
    } else {
      buffer.append("<unknown>");
    }
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Pseudo-Random Function Data (hex): ");
    buffer.append(Functions.toHexString(pseudoRandomFunctionData_));
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

    if (otherObject instanceof PKCS5PBKD2Parameters) {
      PKCS5PBKD2Parameters other = (PKCS5PBKD2Parameters) otherObject;
      equal = (this == other)
          || ((this.saltSource_ == other.saltSource_)
              && Functions.equals(this.saltSourceData_, other.saltSourceData_)
              && (this.iterations_ == other.iterations_)
              && (this.pseudoRandomFunction_ == other.pseudoRandomFunction_) && Functions
                .equals(this.pseudoRandomFunctionData_, other.pseudoRandomFunctionData_));
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
    return ((int) saltSource_) ^ Functions.hashCode(saltSourceData_)
        ^ ((int) iterations_) ^ ((int) pseudoRandomFunction_)
        ^ Functions.hashCode(pseudoRandomFunctionData_);
  }

}
