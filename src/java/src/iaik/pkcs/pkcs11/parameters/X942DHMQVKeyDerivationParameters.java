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

import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.wrapper.CK_X9_42_DHMQV_DERIVE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * This abstract class encapsulates parameters for the X9.42 DH mechanisms
 * Mechanism.X9_42_DH_HYBRID_DERIVE and Mechanism.X9_42_MQV_DERIVE.
 */
public class X942DHMQVKeyDerivationParameters extends X942DH2KeyDerivationParameters {

  private Object publicKey_;

  public X942DHMQVKeyDerivationParameters(long keyDerivationFunction, byte[] sharedData,
      byte[] publicData, long privateDataLength,
      iaik.pkcs.pkcs11.objects.Object privateData, byte[] publicData2,
      iaik.pkcs.pkcs11.objects.Object publicKey) {
    super(keyDerivationFunction, sharedData, publicData, privateDataLength, privateData,
        publicData2);

    publicKey_ = publicKey;
  }

  /*
   * (non-Javadoc)
   * 
   * @see iaik.pkcs.pkcs11.parameters.X942DH2KeyDerivationParameters#clone()
   */
  public java.lang.Object clone() {
    X942DHMQVKeyDerivationParameters clone = (X942DHMQVKeyDerivationParameters) super
        .clone();

    clone.publicKey_ = (iaik.pkcs.pkcs11.objects.Object) this.publicKey_.clone();

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_X9_42_DH2_DERIVE_PARAMS class.
   * 
   * @return This object as a CK_X9_42_DH2_DERIVE_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public java.lang.Object getPKCS11ParamsObject() {
    CK_X9_42_DHMQV_DERIVE_PARAMS params = new CK_X9_42_DHMQV_DERIVE_PARAMS();

    params.kdf = keyDerivationFunction_;
    params.pOtherInfo = otherInfo_;
    params.pPublicData = publicData_;
    params.ulPrivateDataLen = privateDataLength_;
    params.hPrivateData = privateData_.getObjectHandle();
    params.pPublicData2 = publicData2_;
    params.hPublicKey = publicKey_.getObjectHandle();

    return params;
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

    if (otherObject instanceof X942DHMQVKeyDerivationParameters) {
      X942DHMQVKeyDerivationParameters other = (X942DHMQVKeyDerivationParameters) otherObject;
      equal = (this == other)
          || (super.equals(other) && (this.publicKey_.equals(other.publicKey_)));
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
    return super.hashCode() ^ publicKey_.hashCode();
  }

}
