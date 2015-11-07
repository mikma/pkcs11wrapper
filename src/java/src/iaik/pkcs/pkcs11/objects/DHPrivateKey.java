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
 * Objects of this class represent DH private keys as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (prime_ <> null) and (base_ <> null) and (value_ <> null) and (valueBits_ <> null)
 */
public class DHPrivateKey extends PrivateKey {

  /**
   * The prime (p) of this DH key.
   */
  protected ByteArrayAttribute prime_;

  /**
   * The base (g) of this DH key.
   */
  protected ByteArrayAttribute base_;

  /**
   * The private value (x) of this DH key.
   */
  protected ByteArrayAttribute value_;

  /**
   * The length of the value (x) of this DH key in bits.
   */
  protected LongAttribute valueBits_;

  /**
   * Deafult Constructor.
   * 
   */
  public DHPrivateKey() {
    super();
    keyType_.setLongValue(KeyType.DH);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 DH private key.
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
  protected DHPrivateKey(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    keyType_.setLongValue(KeyType.DH);
  }

  /**
   * The getInstance method of the PrivateKey class uses this method to create an instance of a
   * PKCS#11 DH private key.
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
    return new DHPrivateKey(session, objectHandle);
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
  protected static void putAttributesInTable(DHPrivateKey object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.PRIME, object.prime_);
    object.attributeTable_.put(Attribute.BASE, object.base_);
    object.attributeTable_.put(Attribute.VALUE, object.value_);
    object.attributeTable_.put(Attribute.VALUE_BITS, object.valueBits_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    prime_ = new ByteArrayAttribute(Attribute.PRIME);
    base_ = new ByteArrayAttribute(Attribute.BASE);
    value_ = new ByteArrayAttribute(Attribute.VALUE);
    valueBits_ = new LongAttribute(Attribute.VALUE_BITS);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof DHPrivateKey) and (result.equals(this))
   */
  public java.lang.Object clone() {
    DHPrivateKey clone = (DHPrivateKey) super.clone();

    clone.prime_ = (ByteArrayAttribute) this.prime_.clone();
    clone.base_ = (ByteArrayAttribute) this.base_.clone();
    clone.value_ = (ByteArrayAttribute) this.value_.clone();
    clone.valueBits_ = (LongAttribute) this.valueBits_.clone();

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

    if (otherObject instanceof DHPrivateKey) {
      DHPrivateKey other = (DHPrivateKey) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.prime_.equals(other.prime_)
              && this.base_.equals(other.base_) && this.value_.equals(other.value_) && this.valueBits_
                .equals(other.valueBits_));
    }

    return equal;
  }

  /**
   * Gets the prime attribute of this DH key.
   * 
   * @return The prime attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getPrime() {
    return prime_;
  }

  /**
   * Gets the base attribute of this DH key.
   * 
   * @return The base attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getBase() {
    return base_;
  }

  /**
   * Gets the value attribute of this DH key.
   * 
   * @return The value attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getValue() {
    return value_;
  }

  /**
   * Gets the value length attribute of this DH key (in bits).
   * 
   * @return The value length attribute.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getValueBits() {
    return valueBits_;
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

    Object.getAttributeValues(session, objectHandle_, new Attribute[] { prime_, base_,
        valueBits_ });
    // Object.getAttributeValue(session, objectHandle_, prime_);
    // Object.getAttributeValue(session, objectHandle_, base_);
    Object.getAttributeValue(session, objectHandle_, value_);
    // Object.getAttributeValue(session, objectHandle_, valueBits_);
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
    buffer.append("Prime (hex): ");
    buffer.append(prime_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Base (hex): ");
    buffer.append(base_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Value (hex): ");
    buffer.append(value_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Value Bits (dec): ");
    buffer.append(valueBits_.toString(10));

    return buffer.toString();
  }

}
