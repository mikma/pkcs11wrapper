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
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * This is the base class for public (asymmetric) keys. Objects of this class represent public keys
 * as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (subject_ <> null) and (encrypt_ <> null) and (verify_ <> null) and (verifyRecover_
 *             <> null) and (wrap_ <> null)
 */
public class PublicKey extends Key {

  /**
   * The subject attribute of this public key.
   */
  protected ByteArrayAttribute subject_;

  /**
   * True, if this public key can be used for encryption.
   */
  protected BooleanAttribute encrypt_;

  /**
   * True, if this public key can be used for verification.
   */
  protected BooleanAttribute verify_;

  /**
   * True, if this public key can be used for encryption with recovery.
   */
  protected BooleanAttribute verifyRecover_;

  /**
   * True, if this public key can be used for wrapping other keys.
   */
  protected BooleanAttribute wrap_;

  /**
   * True, if this public key can be used for wrapping other keys.
   */
  protected BooleanAttribute trusted_;

  /**
   * Template of the key, that can be wrapped.
   */
  protected AttributeArray wrapTemplate_;

  /**
   * Deafult Constructor.
   * 
   */
  public PublicKey() {
    super();
    objectClass_.setLongValue(ObjectClass.PUBLIC_KEY);
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 public key.
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
  protected PublicKey(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    objectClass_.setLongValue(ObjectClass.PUBLIC_KEY);
  }

  /**
   * The getInstance method of the Object class uses this method to create an instance of a PKCS#11
   * public key. This method reads the key type attribute and calls the getInstance method of the
   * according sub-class. If the key type is a vendor defined it uses the VendorDefinedKeyBuilder
   * set by the application. If no public key could be constructed, this method returns null.
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
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    KeyTypeAttribute keyTypeAttribute = new KeyTypeAttribute();
    getAttributeValue(session, objectHandle, keyTypeAttribute);

    Long keyType = keyTypeAttribute.getLongValue();

    Object newObject;

    if (keyTypeAttribute.isPresent() && (keyType != null)) {
      if (keyType.equals(Key.KeyType.RSA)) {
        newObject = RSAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DSA)) {
        newObject = DSAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.ECDSA)) {
        newObject = ECDSAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DH)) {
        newObject = DHPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.KEA)) {
        newObject = KEAPublicKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.X9_42_DH)) {
        newObject = X942DHPublicKey.getInstance(session, objectHandle);
      } else if ((keyType.longValue() & KeyType.VENDOR_DEFINED.longValue()) != 0L) {
        newObject = getUnknownPublicKey(session, objectHandle);
      } else {
        newObject = getUnknownPublicKey(session, objectHandle);
      }
    } else {
      newObject = getUnknownPublicKey(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a key which has no or an unkown public key type type attribute. This
   * implementation will try to use a vendor defined key builder, if such has been set. If this is
   * impossible or fails, it will create just a simple {@link iaik.pkcs.pkcs11.objects.PublicKey
   * PublicKey }.
   * 
   * @param session
   *          The session to use.
   * @param objectHandle
   *          The handle of the object
   * @return A new Object.
   * @throws TokenException
   *           If no object could be created.
   * @preconditions (session <> null)
   * @postconditions (result <> null)
   */
  protected static Object getUnknownPublicKey(Session session, long objectHandle)
      throws TokenException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    Object newObject;
    if (Key.vendorKeyBuilder_ != null) {
      try {
        newObject = Key.vendorKeyBuilder_.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of public key
        newObject = new PublicKey(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of public key
      newObject = new PublicKey(session, objectHandle);
    }

    return newObject;
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
  protected static void putAttributesInTable(PublicKey object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.SUBJECT, object.subject_);
    object.attributeTable_.put(Attribute.ENCRYPT, object.encrypt_);
    object.attributeTable_.put(Attribute.VERIFY, object.verify_);
    object.attributeTable_.put(Attribute.VERIFY_RECOVER, object.verifyRecover_);
    object.attributeTable_.put(Attribute.WRAP, object.wrap_);
    object.attributeTable_.put(Attribute.TRUSTED, object.trusted_);
    object.attributeTable_.put(Attribute.WRAP_TEMPLATE, object.wrapTemplate_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    subject_ = new ByteArrayAttribute(Attribute.SUBJECT);
    encrypt_ = new BooleanAttribute(Attribute.ENCRYPT);
    verify_ = new BooleanAttribute(Attribute.VERIFY);
    verifyRecover_ = new BooleanAttribute(Attribute.VERIFY_RECOVER);
    wrap_ = new BooleanAttribute(Attribute.WRAP);
    trusted_ = new BooleanAttribute(Attribute.TRUSTED);
    wrapTemplate_ = new AttributeArray(Attribute.WRAP_TEMPLATE);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof PublicKey) and (result.equals(this))
   */
  public java.lang.Object clone() {
    PublicKey clone = (PublicKey) super.clone();

    clone.subject_ = (ByteArrayAttribute) this.subject_.clone();
    clone.encrypt_ = (BooleanAttribute) this.encrypt_.clone();
    clone.verify_ = (BooleanAttribute) this.verify_.clone();
    clone.verifyRecover_ = (BooleanAttribute) this.verifyRecover_.clone();
    clone.wrap_ = (BooleanAttribute) this.wrap_.clone();
    clone.trusted_ = (BooleanAttribute) this.trusted_.clone();
    clone.wrapTemplate_ = (AttributeArray) this.wrapTemplate_.clone();

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

    if (otherObject instanceof PublicKey) {
      PublicKey other = (PublicKey) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.subject_.equals(other.subject_)
              && this.encrypt_.equals(other.encrypt_)
              && this.verify_.equals(other.verify_)
              && this.verifyRecover_.equals(other.verifyRecover_)
              && this.wrap_.equals(other.wrap_) && this.trusted_.equals(other.trusted_) && this.wrapTemplate_
                .equals(other.wrapTemplate_));
    }

    return equal;
  }

  /**
   * Gets the subject attribute of this key.
   * 
   * @return The subject attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getSubject() {
    return subject_;
  }

  /**
   * Gets the encrypt attribute of this key.
   * 
   * @return The encrypt attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getEncrypt() {
    return encrypt_;
  }

  /**
   * Gets the verify attribute of this key.
   * 
   * @return The verify attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getVerify() {
    return verify_;
  }

  /**
   * Gets the verify recover attribute of this key.
   * 
   * @return The verify recover attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getVerifyRecover() {
    return verifyRecover_;
  }

  /**
   * Gets the wrap attribute of this key.
   * 
   * @return The wrap attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getWrap() {
    return wrap_;
  }

  /**
   * Gets the trusted attribute of this key.
   * 
   * @return The trusted attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getTrusted() {
    return trusted_;
  }

  /**
   * Gets the wrap template attribute of this key. This attribute can only be used with PKCS#11
   * modules supporting cryptoki version 2.20 or higher.
   * 
   * @return The wrap template attribute.
   * 
   * @postconditions (result <> null)
   */
  public AttributeArray getWrapTemplate() {
    return wrapTemplate_;
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

    // Object.getAttributeValue(session, objectHandle_, subject_);
    // Object.getAttributeValue(session, objectHandle_, encrypt_);
    // Object.getAttributeValue(session, objectHandle_, verify_);
    // Object.getAttributeValue(session, objectHandle_, verifyRecover_);
    // Object.getAttributeValue(session, objectHandle_, wrap_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { subject_,
        encrypt_, verify_, verifyRecover_, wrap_, trusted_ });
    Object.getAttributeValue(session, objectHandle_, wrapTemplate_);
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
    StringBuffer buffer = new StringBuffer(256);

    buffer.append(super.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Subject (DER, hex): ");
    buffer.append(subject_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Encrypt: ");
    buffer.append(encrypt_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Verify: ");
    buffer.append(verify_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Verify Recover: ");
    buffer.append(verifyRecover_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap: ");
    buffer.append(wrap_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Trusted: ");
    buffer.append(trusted_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap Template: ");
    buffer.append(wrapTemplate_.toString());

    return buffer.toString();
  }

}
