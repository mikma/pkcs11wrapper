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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.wrapper.CK_SSL3_KEY_MAT_OUT;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * Objects of this class encapsulates key material output for the mechanism
 * Mechanism.SSL3_KEY_AND_MAC_DERIVE.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class SSL3KeyMaterialOutParameters implements Parameters {

  /**
   * The resulting Client MAC Secret key.
   */
  protected SecretKey clientMacSecret_;

  /**
   * The resulting Server MAC Secret key.
   */
  protected SecretKey serverMacSecret_;

  /**
   * The resulting Client Secret key.
   */
  protected SecretKey clientKey_;

  /**
   * The resulting Server Secret key.
   */
  protected SecretKey serverKey_;

  /**
   * The initialization vector (IV) created for the client (if any).
   */
  protected byte[] clientIV_;

  /**
   * The initialization vector (IV) created for the server (if any).
   */
  protected byte[] serverIV_;

  /**
   * Create a new SSL3KeyMaterialOutParameters object. It does not take any parameters, because they
   * user does not need to set any of them. The token sets all of them, after a call to DeriveKey
   * using the mechanism Mechanism.SSL3_KEY_AND_MAC_DERIVE. After the call to deriveKey, the members
   * of this object will hold the generated keys and IVs.
   * 
   * @param clientIV
   *          The buffer for the client initialization vector.
   * @param serverIV
   *          The buffer for the server initialization vector.
   * @preconditions (clientIV <> null) and (serverIV <> null)
   * 
   */
  public SSL3KeyMaterialOutParameters(byte[] clientIV, byte[] serverIV) {
    if (clientIV == null) {
      throw new NullPointerException("Argument \"clientIV\" must not be null.");
    }
    if (serverIV == null) {
      throw new NullPointerException("Argument \"serverIV\" must not be null.");
    }

    clientIV_ = clientIV;
    serverIV_ = serverIV;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof SSL3KeyMaterialOutParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    SSL3KeyMaterialOutParameters clone;

    try {
      clone = (SSL3KeyMaterialOutParameters) super.clone();

      clone.clientMacSecret_ = (SecretKey) this.clientMacSecret_.clone();
      clone.serverMacSecret_ = (SecretKey) this.serverMacSecret_.clone();
      clone.clientKey_ = (SecretKey) this.clientKey_.clone();
      clone.serverKey_ = (SecretKey) this.serverKey_.clone();
      clone.clientIV_ = (byte[]) this.clientIV_.clone();
      clone.serverIV_ = (byte[]) this.serverIV_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_SSL3_KEY_MAT_OUT class.
   * 
   * @return This object as a CK_SSL3_KEY_MAT_OUT object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_SSL3_KEY_MAT_OUT params = new CK_SSL3_KEY_MAT_OUT();

    params.hClientMacSecret = (clientMacSecret_ != null) ? clientMacSecret_
        .getObjectHandle() : 0L;
    params.hServerMacSecret = (serverMacSecret_ != null) ? serverMacSecret_
        .getObjectHandle() : 0L;
    params.hClientKey = (clientKey_ != null) ? clientKey_.getObjectHandle() : 0L;
    params.hServerKey = (serverKey_ != null) ? serverKey_.getObjectHandle() : 0L;
    params.pIVClient = clientIV_;
    params.pIVServer = serverIV_;

    return params;
  }

  /**
   * This method takes the key handles from the given input structure, which will be the result
   * after a call to DeriveKey, and creates the SecretKey objects for this object. It also reads the
   * IVs.
   * 
   * @param input
   *          The structure that holds the necessary key handles and IVs.
   * @param session
   *          The session to use for reading attributes. This session must have the appropriate
   *          rights; i.e. it must be a user-session, if it is a private object.
   * @exception TokenException
   *              If reading the secret key object attributes fails.
   * @preconditions (input <> null) and (session <> null)
   * 
   */
  public void setPKCS11ParamsObject(CK_SSL3_KEY_MAT_OUT input, Session session)
      throws TokenException {
    clientMacSecret_ = (SecretKey) iaik.pkcs.pkcs11.objects.Object.getInstance(session,
        input.hClientMacSecret);
    serverMacSecret_ = (SecretKey) iaik.pkcs.pkcs11.objects.Object.getInstance(session,
        input.hServerMacSecret);
    clientKey_ = (SecretKey) iaik.pkcs.pkcs11.objects.Object.getInstance(session,
        input.hClientKey);
    serverKey_ = (SecretKey) iaik.pkcs.pkcs11.objects.Object.getInstance(session,
        input.hServerKey);
    clientIV_ = input.pIVClient;
    serverIV_ = input.pIVServer;
  }

  /**
   * Get the resulting client MAC secret key.
   * 
   * @return The resulting client MAC secret key.
   * 
   * @postconditions (result == null)
   */
  public SecretKey getClientMacSecret() {
    return clientMacSecret_;
  }

  /**
   * Get the resulting server MAC secret key.
   * 
   * @return The resulting server MAC secret key.
   * 
   * @postconditions (result == null)
   */
  public SecretKey getServerMacSecret() {
    return serverMacSecret_;
  }

  /**
   * Get the resulting client secret key.
   * 
   * @return The resulting client secret key.
   * 
   * @postconditions (result == null)
   */
  public SecretKey getClientSecret() {
    return clientKey_;
  }

  /**
   * Get the resulting server secret key.
   * 
   * @return The resulting server secret key.
   * 
   * @postconditions (result == null)
   */
  public SecretKey getServerSecret() {
    return serverKey_;
  }

  /**
   * Get the resulting client initialization vector.
   * 
   * @return The resulting client initialization vector.
   */
  public byte[] getClientIV() {
    return clientIV_;
  }

  /**
   * Get the resulting server initialization vector.
   * 
   * @return The resulting server initialization vector.
   */
  public byte[] getServerIV() {
    return serverIV_;
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
    buffer.append("Client MAC Secret key: ");
    buffer.append(Constants.NEWLINE);
    buffer.append(clientMacSecret_);
    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Server MAC Secret key: ");
    buffer.append(Constants.NEWLINE);
    buffer.append(serverMacSecret_);
    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Client Secret key: ");
    buffer.append(Constants.NEWLINE);
    buffer.append(clientKey_);
    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Server Secret key: ");
    buffer.append(Constants.NEWLINE);
    buffer.append(serverKey_);
    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Client Initializatin Vector (hex): ");
    buffer.append(Functions.toHexString(clientIV_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Server Initializatin Vector (hex): ");
    buffer.append(Functions.toHexString(serverIV_));
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

    if (otherObject instanceof SSL3KeyMaterialOutParameters) {
      SSL3KeyMaterialOutParameters other = (SSL3KeyMaterialOutParameters) otherObject;
      equal = (this == other)
          || ((((this.clientMacSecret_ == null) && (other.clientMacSecret_ == null)) || ((this.clientMacSecret_ != null) && this.clientMacSecret_
              .equals(other.clientMacSecret_)))
              && (((this.serverMacSecret_ == null) && (other.serverMacSecret_ == null)) || ((this.serverMacSecret_ != null) && this.serverMacSecret_
                  .equals(other.serverMacSecret_)))
              && (((this.clientKey_ == null) && (other.clientKey_ == null)) || ((this.clientKey_ != null) && this.clientKey_
                  .equals(other.clientKey_)))
              && (((this.serverKey_ == null) && (other.serverKey_ == null)) || ((this.serverKey_ != null) && this.serverKey_
                  .equals(other.serverKey_)))
              && Functions.equals(this.clientIV_, other.clientIV_) && Functions.equals(
              this.serverIV_, other.serverIV_));
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
    return ((clientMacSecret_ != null) ? clientMacSecret_.hashCode() : 0)
        ^ ((serverMacSecret_ != null) ? serverMacSecret_.hashCode() : 0)
        ^ ((clientKey_ != null) ? clientKey_.hashCode() : 0)
        ^ ((serverKey_ != null) ? serverKey_.hashCode() : 0);
  }

}
