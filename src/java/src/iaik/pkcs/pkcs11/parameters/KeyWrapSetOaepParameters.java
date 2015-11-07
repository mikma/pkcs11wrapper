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
import iaik.pkcs.pkcs11.wrapper.CK_KEY_WRAP_SET_OAEP_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the Mechanism.KEY_WRAP_SET_OAEP.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class KeyWrapSetOaepParameters implements Parameters {

  /**
   * The block contents byte.
   */
  protected byte blockContents_;

  /**
   * The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  protected byte[] x_;

  /**
   * Create a new KEADeriveParameters object with the given attributes.
   * 
   * @param blockContents
   *          The block contents byte.
   * @param x
   *          The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  public KeyWrapSetOaepParameters(byte blockContents, byte[] x) {
    blockContents_ = blockContents;
    x_ = x;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof KeyWrapSetOaepParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    KeyWrapSetOaepParameters clone;

    try {
      clone = (KeyWrapSetOaepParameters) super.clone();

      clone.x_ = (byte[]) this.x_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_KEY_WRAP_SET_OAEP_PARAMS class.
   * 
   * @return This object as a CK_KEY_WRAP_SET_OAEP_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_KEY_WRAP_SET_OAEP_PARAMS params = new CK_KEY_WRAP_SET_OAEP_PARAMS();

    params.bBC = blockContents_;
    params.pX = x_;

    return params;
  }

  /**
   * Get the block contents byte.
   * 
   * @return The block contents byte.
   */
  public byte getBlockContents() {
    return blockContents_;
  }

  /**
   * Get the concatenation of hash of plaintext data (if present) and extra data (if present).
   * 
   * @return The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  public byte[] getX() {
    return x_;
  }

  /**
   * Set the block contents byte.
   * 
   * @param blockContents
   *          The block contents byte.
   */
  public void setBlockContents(byte blockContents) {
    blockContents_ = blockContents;
  }

  /**
   * Set the concatenation of hash of plaintext data (if present) and extra data (if present).
   * 
   * @param x
   *          The concatenation of hash of plaintext data (if present) and extra data (if present).
   */
  public void setX(byte[] x) {
    x_ = x;
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
    buffer.append("Block Contents Byte (hex): ");
    buffer.append(Functions.toHexString(blockContents_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("X (hex): ");
    buffer.append(Functions.toHexString(x_));
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

    if (otherObject instanceof KeyWrapSetOaepParameters) {
      KeyWrapSetOaepParameters other = (KeyWrapSetOaepParameters) otherObject;
      equal = (this == other)
          || ((this.blockContents_ == other.blockContents_) && Functions.equals(this.x_,
              other.x_));
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
    return blockContents_ ^ Functions.hashCode(x_);
  }

}
