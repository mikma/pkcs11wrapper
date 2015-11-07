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

import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DH2_DERIVE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This abstract class encapsulates parameters for the X9.42 DH mechanisms
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (privateData <> null) and (publicData2 <> null)
 */
public class X942DH2KeyDerivationParameters extends X942DH1KeyDerivationParameters {

  /**
   * The length in bytes of the second EC private key.
   */
  protected long privateDataLength_;

  /**
   * The key for the second EC private key value.
   */
  protected iaik.pkcs.pkcs11.objects.Object privateData_;

  /**
   * The other partys second EC public key value.
   */
  protected byte[] publicData2_;

  /**
   * Create a new X942DH1KeyDerivationParameters object with the given attributes.
   * 
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value. One of the values defined
   *          in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other partie's public key value.
   * @param privateDataLength
   *          The length in bytes of the second EC private key.
   * @param privateData
   *          The key for the second X9.42 private key value.
   * @param publicData2
   *          The other partys second X9.42 public key value.
   * @preconditions ((keyDerivationFunction == KeyDerivationFunctionType.NULL) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF_ASN1) or
   *                (keyDerivationFunction == KeyDerivationFunctionType.SHA1_KDF_CONCATENATE)) and
   *                (publicData <> null) and (privateData <> null) and (publicData2 <> null)
   * 
   */
  public X942DH2KeyDerivationParameters(long keyDerivationFunction, byte[] sharedData,
      byte[] publicData, long privateDataLength,
      iaik.pkcs.pkcs11.objects.Object privateData, byte[] publicData2) {
    super(keyDerivationFunction, sharedData, publicData);
    if (privateData == null) {
      throw new NullPointerException("Argument \"privateData\" must not be null.");
    }
    if (publicData2 == null) {
      throw new NullPointerException("Argument \"publicData2\" must not be null.");
    }
    privateDataLength_ = privateDataLength;
    privateData_ = privateData;
    publicData2_ = publicData2;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof X942DH2KeyDerivationParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    X942DH2KeyDerivationParameters clone = (X942DH2KeyDerivationParameters) super.clone();

    clone.privateData_ = (iaik.pkcs.pkcs11.objects.Object) this.privateData_.clone();
    clone.publicData2_ = (byte[]) this.publicData2_.clone();

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_X9_42_DH2_DERIVE_PARAMS class.
   * 
   * @return This object as a CK_X9_42_DH2_DERIVE_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_X9_42_DH2_DERIVE_PARAMS params = new CK_X9_42_DH2_DERIVE_PARAMS();

    params.kdf = keyDerivationFunction_;
    params.pOtherInfo = otherInfo_;
    params.pPublicData = publicData_;
    params.ulPrivateDataLen = privateDataLength_;
    params.hPrivateData = privateData_.getObjectHandle();
    params.pPublicData2 = publicData2_;

    return params;
  }

  /**
   * Get the key for the second X9.42 private key value.
   * 
   * @return The key for the second X9.42 private key value.
   * 
   * @postconditions (result <> null)
   */
  public iaik.pkcs.pkcs11.objects.Object getPrivateData() {
    return privateData_;
  }

  /**
   * Get the length in bytes of the second X9.42 private key.
   * 
   * @return The length in bytes of the second X9.42 private key.
   */
  public long getPrivateDataLength() {
    return privateDataLength_;
  }

  /**
   * Get the other partys second X9.42 public key value.
   * 
   * @return The other partys second X9.42 public key value.
   * 
   * @postconditions (result <> null)
   */
  public byte[] getPublicData2() {
    return publicData2_;
  }

  /**
   * Set the key for the second X9.42 private key value.
   * 
   * @param privateData
   *          The key for the second X9.42 private key value.
   * @preconditions (privateData <> null)
   * 
   */
  public void setPrivateData(iaik.pkcs.pkcs11.objects.Object privateData) {
    if (privateData == null) {
      throw new NullPointerException("Argument \"privateData\" must not be null.");
    }
    privateData_ = privateData;
  }

  /**
   * Set the length in bytes of the second X9.42 private key.
   * 
   * @param privateDataLength
   *          The length in bytes of the second X9.42 private key.
   */
  public void setPrivateDataLength(long privateDataLength) {
    privateDataLength_ = privateDataLength;
  }

  /**
   * Set the other partys second X9.42 public key value.
   * 
   * @param publicData2
   *          The other partys second X9.42 public key value.
   * @preconditions (publicData2 <> null)
   * 
   */
  public void setPublicData2(byte[] publicData2) {
    if (publicData2 == null) {
      throw new NullPointerException("Argument \"publicData2\" must not be null.");
    }
    publicData2_ = publicData2;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   * 
   * @return A string representation of this object.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(super.toString());
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Private Data Length (dec): ");
    buffer.append(privateDataLength_);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Private Data: ");
    buffer.append(privateData_);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Public Data 2: ");
    buffer.append(Functions.toHexString(publicData2_));
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

    if (otherObject instanceof X942DH2KeyDerivationParameters) {
      X942DH2KeyDerivationParameters other = (X942DH2KeyDerivationParameters) otherObject;
      equal = (this == other)
          || (super.equals(other)
              && (this.privateDataLength_ == other.privateDataLength_)
              && this.privateData_.equals(other.privateData_) && Functions.equals(
              this.publicData2_, other.publicData2_));
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
    return super.hashCode() ^ ((int) privateDataLength_) ^ privateData_.hashCode()
        ^ Functions.hashCode(publicData2_);
  }

}
