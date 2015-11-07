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

import iaik.pkcs.pkcs11.wrapper.CK_ECMQV_DERIVE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This class encapsulates parameters for the DH mechanisms Mechanism.ECMQV_DERIVE.
 * 
 */
public class EcMQVKeyDerivationParameters extends DHKeyDerivationParameters {

  /**
   * The data shared between the two parties.
   */
  protected byte[] sharedData_;

  /** the length in bytes of the second EC private key. */
  protected long ulPrivateDataLen_;

  /** key handle for second EC private key value. */
  protected long hPrivateData_;

  /** pointer to other partyâs second EC public key value. */
  protected byte[] pPublicData2_;

  /** Handle to the first partyâs ephemeral public key. */
  protected long publicKey_;

  /**
   * Create a new EcMQVKeyDerivationParameters object with the given attributes.
   * 
   * @param keyDerivationFunction
   *          The key derivation function used on the shared secret value. One of the values defined
   *          in KeyDerivationFunctionType.
   * @param sharedData
   *          The data shared between the two parties.
   * @param publicData
   *          The other partie's public key value.
   * @param ulPrivateDataLen
   *          the length in bytes of the second EC private key
   * @param hPrivateData
   *          Key handle for second EC private key value
   * @param pPublicData2
   *          pointer to other party's second EC public key value
   * @param publicKey
   *          Handle to the first party's ephemeral public key
   */
  public EcMQVKeyDerivationParameters(long keyDerivationFunction, byte[] sharedData,
      byte[] publicData, long ulPrivateDataLen, long hPrivateData, byte[] pPublicData2,
      long publicKey) {
    super(keyDerivationFunction, publicData);
    sharedData_ = sharedData;
    ulPrivateDataLen_ = ulPrivateDataLen;
    hPrivateData_ = hPrivateData;
    pPublicData2_ = pPublicData2;
    publicKey_ = publicKey;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof EcDH1KeyDerivationParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    EcMQVKeyDerivationParameters clone = (EcMQVKeyDerivationParameters) super.clone();

    clone.sharedData_ = (byte[]) this.sharedData_.clone();
    clone.ulPrivateDataLen_ = this.ulPrivateDataLen_;
    clone.hPrivateData_ = this.hPrivateData_;
    clone.pPublicData2_ = (byte[]) this.pPublicData2_.clone();
    clone.publicKey_ = this.publicKey_;

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_ECDH1_DERIVE_PARAMS class.
   * 
   * @return This object as a CK_ECDH1_DERIVE_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_ECMQV_DERIVE_PARAMS params = new CK_ECMQV_DERIVE_PARAMS();

    params.kdf = keyDerivationFunction_;
    params.pSharedData = sharedData_;
    params.pPublicData = publicData_;
    params.ulPrivateDataLen = ulPrivateDataLen_;
    params.hPrivateData = hPrivateData_;
    params.pPublicData2 = pPublicData2_;
    params.publicKey = publicKey_;

    return params;
  }

  /**
   * Get the data shared between the two parties.
   * 
   * @return The data shared between the two parties.
   */
  public byte[] getSharedData() {
    return sharedData_;
  }

  /**
   * Set the data shared between the two parties.
   * 
   * @param sharedData
   *          The data shared between the two parties.
   * @preconditions (sharedData <> null)
   * 
   */
  public void setSharedData(byte[] sharedData) {
    sharedData_ = sharedData;
  }

  /**
   * Get the length in bytes of the second EC private key.
   * 
   * @return the length in bytes of the second EC private key
   */
  public long getUlPrivateDataLen() {
    return ulPrivateDataLen_;
  }

  /**
   * Set the length in bytes of the secon dEC private key.
   * 
   * @param ulPrivateDataLen
   *          the length in bytes of the secon dEC private key
   */
  public void setUlPrivateDataLen(long ulPrivateDataLen) {
    this.ulPrivateDataLen_ = ulPrivateDataLen;
  }

  /**
   * Gets the key handle for the second EC private key value.
   * 
   * @return the key handle for the second EC private key value
   */
  public long gethPrivateData() {
    return hPrivateData_;
  }

  /**
   * Sets the key handle for the second EC private key value.
   * 
   * @param hPrivateData
   *          the key handle for the second EC private key value
   */
  public void sethPrivateData_(long hPrivateData) {
    this.hPrivateData_ = hPrivateData;
  }

  /**
   * Gets the other partyâs second EC public key value.
   * 
   * @return the other partyâs second EC public key value
   */
  public byte[] getpPublicData2() {
    return pPublicData2_;
  }

  /**
   * Sets the other partyâs second EC public key value.
   * 
   * @param pPublicData2
   *          the other partyâs second EC public key value
   */
  public void setpPublicData2_(byte[] pPublicData2) {
    this.pPublicData2_ = pPublicData2;
  }

  /**
   * Gets the handle to the first partyâs ephemeral public key .
   * 
   * @return the Handle to the first partyâs ephemeral public key
   */
  public long getPublicKey() {
    return publicKey_;
  }

  /**
   * Sets the handle to the first partyâs ephemeral public key.
   * 
   * @param publicKey_
   *          the handle to the first partyâs ephemeral public key
   */
  public void setPublicKey(long publicKey) {
    this.publicKey_ = publicKey;
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
    buffer.append("Shared Data: ");
    buffer.append(Functions.toHexString(sharedData_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Private Data Handle: ");
    buffer.append(hPrivateData_);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Public Data 2: ");
    buffer.append(Functions.toHexString(pPublicData2_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("public key handle: ");
    buffer.append(publicKey_);
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

    if (otherObject instanceof EcMQVKeyDerivationParameters) {
      EcMQVKeyDerivationParameters other = (EcMQVKeyDerivationParameters) otherObject;
      equal = (this == other)
          || (super.equals(other)
              && Functions.equals(this.sharedData_, other.sharedData_)
              && this.hPrivateData_ == other.hPrivateData_
              && Functions.equals(this.pPublicData2_, other.pPublicData2_) && this.publicKey_ == other.publicKey_);
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
    return (int) (super.hashCode() ^ Functions.hashCode(sharedData_) ^ this.hPrivateData_
        ^ Functions.hashCode(pPublicData2_) ^ this.publicKey_);
  }

}
