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

package iaik.pkcs.pkcs11.objects;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.Constants;

/**
 * Objects of this class represent RSA private keys as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (modulus_ <> null) and (publicExponent_ <> null) and (privateExponent_ <> null) and
 *             (prime1_ <> null) and (prime2_ <> null) and (exponent1_ <> null) and (exponent2_ <>
 *             null) and (coefficient_ <> null)
 */
public class RSAPrivateKey extends PrivateKey {

  /**
   * The modulus (n) of this RSA key.
   */
  protected ByteArrayAttribute modulus_;

  /**
   * The public exponent (e) of this RSA key.
   */
  protected ByteArrayAttribute publicExponent_;

  /**
   * The private exponent (d) of this RSA key.
   */
  protected ByteArrayAttribute privateExponent_;

  /**
   * The first prime factor (p) of this RSA key, for use with CRT.
   */
  protected ByteArrayAttribute prime1_;

  /**
   * The second prime factor (q) of this RSA key, for use with CRT.
   */
  protected ByteArrayAttribute prime2_;

  /**
   * The first exponent (d mod (p-1)) of this RSA key, for use with CRT.
   */
  protected ByteArrayAttribute exponent1_;

  /**
   * The second exponent (d mod (q-1)) of this RSA key, for use with CRT.
   */
  protected ByteArrayAttribute exponent2_;

  /**
   * The coefficient (1/q mod (p)) of this RSA key, for use with CRT.
   */
  protected ByteArrayAttribute coefficient_;

  /**
   * Deafult Constructor.
   * 
   */
  public RSAPrivateKey() {
    super();
    keyType_.setLongValue(KeyType.RSA);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 RSA private key.
   * 
   * @param session
   *          The session to use for reading attributes. This session must have the appropriate
   *          rights; i.e. it must be a user-session, if it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @exception TokenException
   *              If getting the attributes failed.
   * @preconditions (session <> null)
   * 
   */
  protected RSAPrivateKey(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    keyType_.setLongValue(KeyType.RSA);
  }

  /**
   * The getInstance method of the PrivateKey class uses this method to create an instance of a
   * PKCS#11 RSA private key.
   * 
   * @param session
   *          The session to use for reading attributes. This session must have the appropriate
   *          rights; i.e. it must be a user-session, if it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @return The object representing the PKCS#11 object. The returned object can be casted to the
   *         according sub-class.
   * @exception TokenException
   *              If getting the attributes failed.
   * @preconditions (session <> null)
   * @postconditions (result <> null)
   */
  public static Object getInstance(Session session, long objectHandle)
      throws TokenException {
    return new RSAPrivateKey(session, objectHandle);
  }

  /**
   * Put all attributes of the given object into the attributes table of this object. This method is
   * only static to be able to access invoke the implementation of this method for each class
   * separately (see use in clone()).
   * 
   * @param object
   *          The object to handle.
   * @preconditions (object <> null)
   * 
   */
  protected static void putAttributesInTable(RSAPrivateKey object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.MODULUS, object.modulus_);
    object.attributeTable_.put(Attribute.PUBLIC_EXPONENT, object.publicExponent_);
    object.attributeTable_.put(Attribute.PRIVATE_EXPONENT, object.privateExponent_);
    object.attributeTable_.put(Attribute.PRIME_1, object.prime1_);
    object.attributeTable_.put(Attribute.PRIME_2, object.prime2_);
    object.attributeTable_.put(Attribute.EXPONENT_1, object.exponent1_);
    object.attributeTable_.put(Attribute.EXPONENT_2, object.exponent2_);
    object.attributeTable_.put(Attribute.COEFFICIENT, object.coefficient_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    modulus_ = new ByteArrayAttribute(Attribute.MODULUS);
    publicExponent_ = new ByteArrayAttribute(Attribute.PUBLIC_EXPONENT);
    privateExponent_ = new ByteArrayAttribute(Attribute.PRIVATE_EXPONENT);
    prime1_ = new ByteArrayAttribute(Attribute.PRIME_1);
    prime2_ = new ByteArrayAttribute(Attribute.PRIME_2);
    exponent1_ = new ByteArrayAttribute(Attribute.EXPONENT_1);
    exponent2_ = new ByteArrayAttribute(Attribute.EXPONENT_2);
    coefficient_ = new ByteArrayAttribute(Attribute.COEFFICIENT);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof RSAPrivateKey) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    RSAPrivateKey clone = (RSAPrivateKey) super.clone();

    clone.modulus_ = (ByteArrayAttribute) this.modulus_.clone();
    clone.publicExponent_ = (ByteArrayAttribute) this.publicExponent_.clone();
    clone.privateExponent_ = (ByteArrayAttribute) this.privateExponent_.clone();
    clone.prime1_ = (ByteArrayAttribute) this.prime1_.clone();
    clone.prime2_ = (ByteArrayAttribute) this.prime2_.clone();
    clone.exponent1_ = (ByteArrayAttribute) this.exponent1_.clone();
    clone.exponent2_ = (ByteArrayAttribute) this.exponent2_.clone();
    clone.coefficient_ = (ByteArrayAttribute) this.coefficient_.clone();

    putAttributesInTable(clone); // put all cloned attributes into the new table

    return clone;
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

    if (otherObject instanceof RSAPrivateKey) {
      RSAPrivateKey other = (RSAPrivateKey) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.modulus_.equals(other.modulus_)
              && this.publicExponent_.equals(other.publicExponent_)
              && this.privateExponent_.equals(other.privateExponent_)
              && this.prime1_.equals(other.prime1_) && this.prime2_.equals(other.prime2_)
              && this.exponent1_.equals(other.exponent1_)
              && this.exponent2_.equals(other.exponent2_) && this.coefficient_
                .equals(other.coefficient_));
    }

    return equal;
  }

  /**
   * Gets the modulus attribute of this RSA key.
   * 
   * @return The modulus attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getModulus() {
    return modulus_;
  }

  /**
   * Gets the public exponent attribute of this RSA key.
   * 
   * @return The public exponent attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getPublicExponent() {
    return publicExponent_;
  }

  /**
   * Gets the private exponent attribute of this RSA key.
   * 
   * @return The private exponent attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getPrivateExponent() {
    return privateExponent_;
  }

  /**
   * Gets the first prime attribute of this RSA key.
   * 
   * @return The first prime attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getPrime1() {
    return prime1_;
  }

  /**
   * Gets the second prime attribute of this RSA key.
   * 
   * @return The second prime attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getPrime2() {
    return prime2_;
  }

  /**
   * Gets the first exponent (d mod (p-1)) attribute of this RSA key.
   * 
   * @return The first exponent (d mod (p-1)) attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getExponent1() {
    return exponent1_;
  }

  /**
   * Gets the second exponent (d mod (q-1)) attribute of this RSA key.
   * 
   * @return The second exponent (d mod (q-1)) attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getExponent2() {
    return exponent2_;
  }

  /**
   * Gets the coefficient (1/q mod (p)) attribute of this RSA key.
   * 
   * @return The coefficient (1/q mod (p)) attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getCoefficient() {
    return coefficient_;
  }

  /**
   * Read the values of the attributes of this object from the token.
   * 
   * @param session
   *          The session handle to use for reading attributes. This session must have the
   *          appropriate rights; i.e. it must be a user-session, if it is a private object.
   * @exception TokenException
   *              If getting the attributes failed.
   * @preconditions (session <> null)
   * 
   */
  public void readAttributes(Session session) throws TokenException {
    super.readAttributes(session);

    // Object.getAttributeValue(session, objectHandle_, modulus_);
    // Object.getAttributeValue(session, objectHandle_, publicExponent_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { modulus_,
        publicExponent_ });
    // Object.getAttributeValue(session, objectHandle_, privateExponent_);
    // Object.getAttributeValue(session, objectHandle_, prime1_);
    // Object.getAttributeValue(session, objectHandle_, prime2_);
    // Object.getAttributeValue(session, objectHandle_, exponent1_);
    // Object.getAttributeValue(session, objectHandle_, exponent2_);
    // Object.getAttributeValue(session, objectHandle_, coefficient_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { privateExponent_,
        prime1_, prime2_, exponent1_, exponent2_, coefficient_ });
  }

  /**
   * This method returns a string representation of the current object. The output is only for
   * debugging purposes and should not be used for other purposes.
   * 
   * @return A string presentation of this object for debugging output.
   * 
   * @postconditions (result <> null)
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer(1024);

    buffer.append(super.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Modulus (hex): ");
    buffer.append(modulus_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Public Exponent (hex): ");
    buffer.append(publicExponent_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Private Exponent (hex): ");
    buffer.append(privateExponent_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Prime 1 (hex): ");
    buffer.append(prime1_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Prime 2 (hex): ");
    buffer.append(prime2_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Exponent 1 (hex): ");
    buffer.append(exponent1_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Exponent 2 (hex): ");
    buffer.append(exponent2_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Coefficient (hex): ");
    buffer.append(coefficient_.toString());

    return buffer.toString();
  }

}
