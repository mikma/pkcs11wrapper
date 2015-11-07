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
import iaik.pkcs.pkcs11.wrapper.CK_KEY_DERIVATION_STRING_DATA;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for several key derivation mechanisms that need string data as
 * parameter.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (data_ <> null)
 */
public class KeyDerivationStringDataParameters implements Parameters {

  /**
   * The data.
   */
  protected byte[] data_;

  /**
   * Create a new KeyDerivationStringDataParameters object with the given data.
   * 
   * @param data
   *          The string data.
   * @preconditions (data <> null)
   * 
   */
  public KeyDerivationStringDataParameters(byte[] data) {
    if (data == null) {
      throw new NullPointerException("Argument \"data\" must not be null.");
    }
    data_ = data;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof KeyDerivationStringDataParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    KeyDerivationStringDataParameters clone;

    try {
      clone = (KeyDerivationStringDataParameters) super.clone();

      clone.data_ = (byte[]) this.data_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as a byte array.
   * 
   * @return This object as a byte array.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_KEY_DERIVATION_STRING_DATA params = new CK_KEY_DERIVATION_STRING_DATA();

    params.pData = data_;

    return params;
  }

  /**
   * Get the string data.
   * 
   * @return The string data.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getData() {
    return data_;
  }

  /**
   * Set the string data.
   * 
   * @param data
   *          The string data.
   * @preconditions (data <> null)
   * 
   */
  public void setData(byte[] data) {
    if (data == null) {
      throw new NullPointerException("Argument \"data\" must not be null.");
    }
    data_ = data;
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
    buffer.append("String data (hex): ");
    buffer.append(Functions.toHexString(data_));
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

    if (otherObject instanceof KeyDerivationStringDataParameters) {
      KeyDerivationStringDataParameters other = (KeyDerivationStringDataParameters) otherObject;
      equal = (this == other) || Functions.equals(this.data_, other.data_);
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
    return Functions.hashCode(data_);
  }

}
