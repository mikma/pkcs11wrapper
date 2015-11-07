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
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * This is the base class for private (asymmetric) keys. Objects of this class represent private
 * keys as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (subject_ <> null) and (sensitive_ <> null) and (secondaryAuth_ <> null) and
 *             (authPinFlags_ <> null) and (decrypt_ <> null) and (sign_ <> null) and (signRecover_
 *             <> null) and (unwrap_ <> null) and (extractable_ <> null) and (alwaysSensitive_ <>
 *             null) and (neverExtractable_ <> null)
 */
public class PrivateKey extends Key {

  /**
   * The subject of this private key.
   */
  protected ByteArrayAttribute subject_;

  /**
   * True, if this private key is sensitive.
   */
  protected BooleanAttribute sensitive_;

  /**
   * True, if this private key supports secondary authentication.
   */
  protected BooleanAttribute secondaryAuth_;

  /**
   * The authentication flags for secondary authentication. Only defined, if the secondaryAuth_ is
   * set.
   */
  protected LongAttribute authPinFlags_;

  /**
   * True, if this private key can be used for encryption.
   */
  protected BooleanAttribute decrypt_;

  /**
   * True, if this private key can be used for signing.
   */
  protected BooleanAttribute sign_;

  /**
   * True, if this private key can be used for signing with recover.
   */
  protected BooleanAttribute signRecover_;

  /**
   * True, if this private key can be used for unwrapping wrapped keys.
   */
  protected BooleanAttribute unwrap_;

  /**
   * True, if this private key can not be extracted from the token.
   */
  protected BooleanAttribute extractable_;

  /**
   * True, if this private key was always sensitive.
   */
  protected BooleanAttribute alwaysSensitive_;

  /**
   * True, if this private key was never extractable.
   */
  protected BooleanAttribute neverExtractable_;

  /**
   * True, if this private key can only be wrapped with a wrapping key having set the attribute
   * trusted to true.
   */
  protected BooleanAttribute wrapWithTrusted_;

  /**
   * Template of the key, that can be unwrapped.
   */
  protected AttributeArray unwrapTemplate_;

  /**
   * True, if the user has to supply the PIN for each use (sign or decrypt) with the key.
   */
  protected BooleanAttribute alwaysAuthenticate_;

  /**
   * Default Constructor.
   * 
   */
  public PrivateKey() {
    super();
    objectClass_.setLongValue(ObjectClass.PRIVATE_KEY);
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 private key.
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
  protected PrivateKey(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    objectClass_.setLongValue(ObjectClass.PRIVATE_KEY);
  }

  /**
   * The getInstance method of the Object class uses this method to create an instance of a PKCS#11
   * private key. This method reads the key type attribute and calls the getInstance method of the
   * according sub-class. If the key type is a vendor defined it uses the VendorDefinedKeyBuilder
   * set by the application. If no private key could be constructed, this method returns null.
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
        newObject = RSAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DSA)) {
        newObject = DSAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.ECDSA)) {
        newObject = ECDSAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DH)) {
        newObject = DHPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.KEA)) {
        newObject = KEAPrivateKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.X9_42_DH)) {
        newObject = X942DHPrivateKey.getInstance(session, objectHandle);
      } else if ((keyType.longValue() & KeyType.VENDOR_DEFINED.longValue()) != 0L) {
        newObject = getUnknownPrivateKey(session, objectHandle);
      } else {
        newObject = getUnknownPrivateKey(session, objectHandle);
      }
    } else {
      newObject = getUnknownPrivateKey(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a key which has no or an unkown private key type type attribute. This
   * implementation will try to use a vendor defined key builder, if such has been set. If this is
   * impossible or fails, it will create just a simple {@link iaik.pkcs.pkcs11.objects.PrivateKey
   * PrivateKey }.
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
  protected static Object getUnknownPrivateKey(Session session, long objectHandle)
      throws TokenException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    Object newObject;
    if (Key.vendorKeyBuilder_ != null) {
      try {
        newObject = Key.vendorKeyBuilder_.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of private key
        newObject = new PrivateKey(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of private key
      newObject = new PrivateKey(session, objectHandle);
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
  protected static void putAttributesInTable(PrivateKey object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.SUBJECT, object.subject_);
    object.attributeTable_.put(Attribute.SENSITIVE, object.sensitive_);
    object.attributeTable_.put(Attribute.SECONDARY_AUTH, object.secondaryAuth_);
    object.attributeTable_.put(Attribute.AUTH_PIN_FLAGS, object.authPinFlags_);
    object.attributeTable_.put(Attribute.DECRYPT, object.decrypt_);
    object.attributeTable_.put(Attribute.SIGN, object.sign_);
    object.attributeTable_.put(Attribute.SIGN_RECOVER, object.signRecover_);
    object.attributeTable_.put(Attribute.UNWRAP, object.unwrap_);
    object.attributeTable_.put(Attribute.EXTRACTABLE, object.extractable_);
    object.attributeTable_.put(Attribute.ALWAYS_SENSITIVE, object.alwaysSensitive_);
    object.attributeTable_.put(Attribute.NEVER_EXTRACTABLE, object.neverExtractable_);
    object.attributeTable_.put(Attribute.WRAP_WITH_TRUSTED, object.wrapWithTrusted_);
    object.attributeTable_.put(Attribute.UNWRAP_TEMPLATE, object.unwrapTemplate_);
    object.attributeTable_.put(Attribute.ALWAYS_AUTHENTICATE, object.alwaysAuthenticate_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    subject_ = new ByteArrayAttribute(Attribute.SUBJECT);
    sensitive_ = new BooleanAttribute(Attribute.SENSITIVE);
    secondaryAuth_ = new BooleanAttribute(Attribute.SECONDARY_AUTH);
    authPinFlags_ = new LongAttribute(Attribute.AUTH_PIN_FLAGS);
    decrypt_ = new BooleanAttribute(Attribute.DECRYPT);
    sign_ = new BooleanAttribute(Attribute.SIGN);
    signRecover_ = new BooleanAttribute(Attribute.SIGN_RECOVER);
    unwrap_ = new BooleanAttribute(Attribute.UNWRAP);
    extractable_ = new BooleanAttribute(Attribute.EXTRACTABLE);
    alwaysSensitive_ = new BooleanAttribute(Attribute.ALWAYS_SENSITIVE);
    neverExtractable_ = new BooleanAttribute(Attribute.NEVER_EXTRACTABLE);
    wrapWithTrusted_ = new BooleanAttribute(Attribute.WRAP_WITH_TRUSTED);
    unwrapTemplate_ = new AttributeArray(Attribute.UNWRAP_TEMPLATE);
    alwaysAuthenticate_ = new BooleanAttribute(Attribute.ALWAYS_AUTHENTICATE);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof PrivateKey) and (result.equals(this))
   */
  public java.lang.Object clone() {
    PrivateKey clone = (PrivateKey) super.clone();

    clone.subject_ = (ByteArrayAttribute) this.subject_.clone();
    clone.sensitive_ = (BooleanAttribute) this.sensitive_.clone();
    clone.secondaryAuth_ = (BooleanAttribute) this.secondaryAuth_.clone();
    clone.authPinFlags_ = (LongAttribute) this.authPinFlags_.clone();
    clone.decrypt_ = (BooleanAttribute) this.decrypt_.clone();
    clone.sign_ = (BooleanAttribute) this.sign_.clone();
    clone.signRecover_ = (BooleanAttribute) this.signRecover_.clone();
    clone.unwrap_ = (BooleanAttribute) this.unwrap_.clone();
    clone.extractable_ = (BooleanAttribute) this.extractable_.clone();
    clone.alwaysSensitive_ = (BooleanAttribute) this.alwaysSensitive_.clone();
    clone.neverExtractable_ = (BooleanAttribute) this.neverExtractable_.clone();
    clone.wrapWithTrusted_ = (BooleanAttribute) this.wrapWithTrusted_.clone();
    clone.unwrapTemplate_ = (AttributeArray) this.unwrapTemplate_.clone();
    clone.alwaysAuthenticate_ = (BooleanAttribute) this.alwaysAuthenticate_.clone();

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

    if (otherObject instanceof PrivateKey) {
      PrivateKey other = (PrivateKey) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.subject_.equals(other.subject_)
              && this.sensitive_.equals(other.sensitive_)
              && this.secondaryAuth_.equals(other.secondaryAuth_)
              && this.authPinFlags_.equals(other.authPinFlags_)
              && this.decrypt_.equals(other.decrypt_) && this.sign_.equals(other.sign_)
              && this.signRecover_.equals(other.signRecover_)
              && this.unwrap_.equals(other.unwrap_)
              && this.extractable_.equals(other.extractable_)
              && this.alwaysSensitive_.equals(other.alwaysSensitive_)
              && this.neverExtractable_.equals(other.neverExtractable_)
              && this.wrapWithTrusted_.equals(other.wrapWithTrusted_)
              && this.unwrapTemplate_.equals(other.unwrapTemplate_) && this.alwaysAuthenticate_
                .equals(other.alwaysAuthenticate_));
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
   * Gets the sensitive attribute of this key.
   * 
   * @return The sensitive attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getSensitive() {
    return sensitive_;
  }

  /**
   * Gets the secondary authentication attribute of this key.
   * 
   * @return The secondary authentication attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getSecondaryAuth() {
    return secondaryAuth_;
  }

  /**
   * Gets the authentication flags for secondary authentication of this key.
   * 
   * @return The authentication flags for secondary authentication attribute.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getAuthPinFlags() {
    return authPinFlags_;
  }

  /**
   * Gets the decrypt attribute of this key.
   * 
   * @return The decrypt attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getDecrypt() {
    return decrypt_;
  }

  /**
   * Gets the sign attribute of this key.
   * 
   * @return The sign attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getSign() {
    return sign_;
  }

  /**
   * Gets the sign recover attribute of this key.
   * 
   * @return The sign recover attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getSignRecover() {
    return signRecover_;
  }

  /**
   * Gets the unwrap attribute of this key.
   * 
   * @return The unwrap attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getUnwrap() {
    return unwrap_;
  }

  /**
   * Gets the extractable attribute of this key.
   * 
   * @return The extractable attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getExtractable() {
    return extractable_;
  }

  /**
   * Gets the always sensitive attribute of this key.
   * 
   * @return The always sensitive attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getAlwaysSensitive() {
    return alwaysSensitive_;
  }

  /**
   * Gets the never extractable attribute of this key.
   * 
   * @return The never extractable attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getNeverExtractable() {
    return neverExtractable_;
  }

  /**
   * Gets the wrap with trusted attribute of this key.
   * 
   * @return The wrap with trusted attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getWrapWithTrusted() {
    return wrapWithTrusted_;
  }

  /**
   * Gets the unwrap template attribute of this key. This attribute can only be used with PKCS#11
   * modules supporting cryptoki version 2.20 or higher.
   * 
   * @return The unwrap template attribute.
   * 
   * @postconditions (result <> null)
   */
  public AttributeArray getUnwrapTemplate() {
    return unwrapTemplate_;
  }

  /**
   * Gets the always authenticate attribute of this key.
   * 
   * @return The always authenticate attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getAlwaysAuthenticate() {
    return alwaysAuthenticate_;
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
    // Object.getAttributeValue(session, objectHandle_, sensitive_);
    // Object.getAttributeValue(session, objectHandle_, secondaryAuth_);
    // Object.getAttributeValue(session, objectHandle_, authPinFlags_);
    // Object.getAttributeValue(session, objectHandle_, decrypt_);
    // Object.getAttributeValue(session, objectHandle_, sign_);
    // Object.getAttributeValue(session, objectHandle_, signRecover_);
    // Object.getAttributeValue(session, objectHandle_, unwrap_);
    // Object.getAttributeValue(session, objectHandle_, extractable_);
    // Object.getAttributeValue(session, objectHandle_, alwaysSensitive_);
    // Object.getAttributeValue(session, objectHandle_, neverExtractable_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { subject_,
        sensitive_, secondaryAuth_, authPinFlags_, decrypt_, sign_, signRecover_,
        unwrap_, extractable_, alwaysSensitive_, neverExtractable_, wrapWithTrusted_,
        alwaysAuthenticate_ });
    Object.getAttributeValue(session, objectHandle_, unwrapTemplate_);
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
    buffer.append("Subject (DER, hex): ");
    buffer.append(subject_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Sensitive: ");
    buffer.append(sensitive_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Secondary Authentication: ");
    buffer.append(secondaryAuth_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Secondary Authentication PIN Flags: ");
    if (authPinFlags_.isPresent() && !authPinFlags_.isSensitive()
        && (authPinFlags_.getLongValue() != null)) {
      long authFlagsValue = authPinFlags_.getLongValue().longValue();

      buffer.append(Constants.NEWLINE);
      buffer.append(Constants.INDENT);
      buffer.append(Constants.INDENT);
      buffer.append("User PIN-Count low: ");
      buffer.append((authFlagsValue & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L);

      buffer.append(Constants.NEWLINE);
      buffer.append(Constants.INDENT);
      buffer.append(Constants.INDENT);
      buffer.append("User PIN final Try: ");
      buffer.append((authFlagsValue & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L);

      buffer.append(Constants.NEWLINE);
      buffer.append(Constants.INDENT);
      buffer.append(Constants.INDENT);
      buffer.append("User PIN locked: ");
      buffer.append((authFlagsValue & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L);

      buffer.append(Constants.NEWLINE);
      buffer.append(Constants.INDENT);
      buffer.append(Constants.INDENT);
      buffer.append("User PIN to be changed: ");
      buffer.append((authFlagsValue & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L);
    } else {
      buffer.append(authPinFlags_.toString());
    }

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Decrypt: ");
    buffer.append(decrypt_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Sign: ");
    buffer.append(sign_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Sign Recover: ");
    buffer.append(signRecover_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Unwrap: ");
    buffer.append(unwrap_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Extractable: ");
    buffer.append(extractable_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Always Sensitive: ");
    buffer.append(alwaysSensitive_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Never Extractable: ");
    buffer.append(neverExtractable_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap With Trusted: ");
    buffer.append(wrapWithTrusted_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Unwrap Template: ");
    buffer.append(unwrapTemplate_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Always Authenticate: ");
    buffer.append(alwaysAuthenticate_.toString());

    return buffer.toString();
  }

}
