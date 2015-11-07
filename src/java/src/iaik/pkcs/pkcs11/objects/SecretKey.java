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
 * This is the base class for secret (symmetric) keys. Objects of this class represent secret keys
 * as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (sensitive_ <> null) and (encrypt_ <> null) and (decrypt_ <> null) and (sign_ <>
 *             null) and (verify_ <> null) and (wrap_ <> null) and (unwrap_ <> null) and
 *             (extractable_ <> null) and (alwaysSensitive_ <> null) and (neverExtractable_ <> null)
 */
public class SecretKey extends Key {

  /**
   * True, if this key is sensitive.
   */
  protected BooleanAttribute sensitive_;

  /**
   * True, if this key can be used for encryption.
   */
  protected BooleanAttribute encrypt_;

  /**
   * True, if this key can be used for decryption.
   */
  protected BooleanAttribute decrypt_;

  /**
   * True, if this key can be used for signing.
   */
  protected BooleanAttribute sign_;

  /**
   * True, if this key can be used for verification.
   */
  protected BooleanAttribute verify_;

  /**
   * True, if this key can be used for wrapping other keys.
   */
  protected BooleanAttribute wrap_;

  /**
   * True, if this key can be used for unwrapping other keys.
   */
  protected BooleanAttribute unwrap_;

  /**
   * True, if this key is extractable from the token.
   */
  protected BooleanAttribute extractable_;

  /**
   * True, if this key was always sensitive.
   */
  protected BooleanAttribute alwaysSensitive_;

  /**
   * True, if this key was never extractable.
   */
  protected BooleanAttribute neverExtractable_;

  /**
   * Key checksum of this private key.
   */
  protected ByteArrayAttribute checkValue_;

  /**
   * True, if this private key can only be wrapped with a wrapping key having set the attribute
   * trusted to true.
   */
  protected BooleanAttribute wrapWithTrusted_;

  /**
   * True, if this public key can be used for wrapping other keys.
   */
  protected BooleanAttribute trusted_;

  /**
   * Template of the key, that can be wrapped.
   */
  protected AttributeArray wrapTemplate_;

  /**
   * Template of the key, that can be unwrapped.
   */
  protected AttributeArray unwrapTemplate_;

  /**
   * Default Constructor.
   * 
   */
  public SecretKey() {
    super();
    objectClass_.setLongValue(ObjectClass.SECRET_KEY);
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 secret key.
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
  protected SecretKey(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    objectClass_.setLongValue(ObjectClass.SECRET_KEY);
  }

  /**
   * The getInstance method of the Object class uses this method to create an instance of a PKCS#11
   * secret key. This method reads the key type attribute and calls the getInstance method of the
   * according sub-class. If the key type is a vendor defined it uses the VendorDefinedKeyBuilder
   * set by the application. If no secret key could be constructed, this method returns null.
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
      if (keyType.equals(Key.KeyType.DES)) {
        newObject = DESSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DES2)) {
        newObject = DES2SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DES3)) {
        newObject = DES3SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.AES)) {
        newObject = AESSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.RC2)) {
        newObject = RC2SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.RC4)) {
        newObject = RC4SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.RC5)) {
        newObject = RC5SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.IDEA)) {
        newObject = IDEASecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.GENERIC_SECRET)) {
        newObject = GenericSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.CAST)) {
        newObject = CASTSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.CAST3)) {
        newObject = CAST3SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.CAST5)) {
        newObject = CAST5SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.CAST128)) {
        newObject = CAST128SecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.BLOWFISH)) {
        newObject = BlowfishSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.TWOFISH)) {
        newObject = TwofishSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.SKIPJACK)) {
        newObject = SkipJackSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.BATON)) {
        newObject = BatonSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.JUNIPER)) {
        newObject = JuniperSecretKey.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.CDMF)) {
        newObject = CDMFSecretKey.getInstance(session, objectHandle);
      } else if ((keyType.longValue() & KeyType.VENDOR_DEFINED.longValue()) != 0L) {
        newObject = getUnknownSecretKey(session, objectHandle);
      } else {
        newObject = getUnknownSecretKey(session, objectHandle);
      }
    } else {
      newObject = getUnknownSecretKey(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a key which has no or an unkown secret key type type attribute. This
   * implementation will try to use a vendor defined key builder, if such has been set. If this is
   * impossible or fails, it will create just a simple {@link iaik.pkcs.pkcs11.objects.SecretKey
   * SecretKey }.
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
  protected static Object getUnknownSecretKey(Session session, long objectHandle)
      throws TokenException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    Object newObject;
    if (Key.vendorKeyBuilder_ != null) {
      try {
        newObject = Key.vendorKeyBuilder_.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of secret key
        newObject = new SecretKey(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of secret key
      newObject = new SecretKey(session, objectHandle);
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
  protected static void putAttributesInTable(SecretKey object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.SENSITIVE, object.sensitive_);
    object.attributeTable_.put(Attribute.ENCRYPT, object.encrypt_);
    object.attributeTable_.put(Attribute.DECRYPT, object.decrypt_);
    object.attributeTable_.put(Attribute.SIGN, object.sign_);
    object.attributeTable_.put(Attribute.VERIFY, object.verify_);
    object.attributeTable_.put(Attribute.WRAP, object.wrap_);
    object.attributeTable_.put(Attribute.UNWRAP, object.unwrap_);
    object.attributeTable_.put(Attribute.EXTRACTABLE, object.extractable_);
    object.attributeTable_.put(Attribute.ALWAYS_SENSITIVE, object.alwaysSensitive_);
    object.attributeTable_.put(Attribute.NEVER_EXTRACTABLE, object.neverExtractable_);
    object.attributeTable_.put(Attribute.CHECK_VALUE, object.checkValue_);
    object.attributeTable_.put(Attribute.WRAP_WITH_TRUSTED, object.wrapWithTrusted_);
    object.attributeTable_.put(Attribute.TRUSTED, object.trusted_);
    object.attributeTable_.put(Attribute.WRAP_TEMPLATE, object.wrapTemplate_);
    object.attributeTable_.put(Attribute.UNWRAP_TEMPLATE, object.unwrapTemplate_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    sensitive_ = new BooleanAttribute(Attribute.SENSITIVE);
    encrypt_ = new BooleanAttribute(Attribute.ENCRYPT);
    decrypt_ = new BooleanAttribute(Attribute.DECRYPT);
    sign_ = new BooleanAttribute(Attribute.SIGN);
    verify_ = new BooleanAttribute(Attribute.VERIFY);
    wrap_ = new BooleanAttribute(Attribute.WRAP);
    unwrap_ = new BooleanAttribute(Attribute.UNWRAP);
    extractable_ = new BooleanAttribute(Attribute.EXTRACTABLE);
    alwaysSensitive_ = new BooleanAttribute(Attribute.ALWAYS_SENSITIVE);
    neverExtractable_ = new BooleanAttribute(Attribute.NEVER_EXTRACTABLE);
    checkValue_ = new ByteArrayAttribute(Attribute.CHECK_VALUE);
    wrapWithTrusted_ = new BooleanAttribute(Attribute.WRAP_WITH_TRUSTED);
    trusted_ = new BooleanAttribute(Attribute.TRUSTED);
    wrapTemplate_ = new AttributeArray(Attribute.WRAP_TEMPLATE);
    unwrapTemplate_ = new AttributeArray(Attribute.UNWRAP_TEMPLATE);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof SecretKey) and (result.equals(this))
   */
  public java.lang.Object clone() {
    SecretKey clone = (SecretKey) super.clone();

    clone.sensitive_ = (BooleanAttribute) this.sensitive_.clone();
    clone.encrypt_ = (BooleanAttribute) this.encrypt_.clone();
    clone.decrypt_ = (BooleanAttribute) this.decrypt_.clone();
    clone.sign_ = (BooleanAttribute) this.sign_.clone();
    clone.verify_ = (BooleanAttribute) this.verify_.clone();
    clone.wrap_ = (BooleanAttribute) this.wrap_.clone();
    clone.unwrap_ = (BooleanAttribute) this.unwrap_.clone();
    clone.extractable_ = (BooleanAttribute) this.extractable_.clone();
    clone.alwaysSensitive_ = (BooleanAttribute) this.alwaysSensitive_.clone();
    clone.neverExtractable_ = (BooleanAttribute) this.neverExtractable_.clone();
    clone.checkValue_ = (ByteArrayAttribute) this.checkValue_.clone();
    clone.wrapWithTrusted_ = (BooleanAttribute) this.wrapWithTrusted_.clone();
    clone.trusted_ = (BooleanAttribute) this.trusted_.clone();
    clone.wrapTemplate_ = (AttributeArray) this.wrapTemplate_.clone();
    clone.unwrapTemplate_ = (AttributeArray) this.unwrapTemplate_.clone();

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

    if (otherObject instanceof SecretKey) {
      SecretKey other = (SecretKey) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.sensitive_.equals(other.sensitive_)
              && this.encrypt_.equals(other.encrypt_)
              && this.decrypt_.equals(other.decrypt_) && this.sign_.equals(other.sign_)
              && this.verify_.equals(other.verify_) && this.wrap_.equals(other.wrap_)
              && this.unwrap_.equals(other.unwrap_)
              && this.extractable_.equals(other.extractable_)
              && this.alwaysSensitive_.equals(other.alwaysSensitive_)
              && this.neverExtractable_.equals(other.neverExtractable_)
              && this.checkValue_.equals(other.checkValue_)
              && this.wrapWithTrusted_.equals(other.wrapWithTrusted_)
              && this.trusted_.equals(other.trusted_)
              && this.wrapTemplate_.equals(other.wrapTemplate_) && this.unwrapTemplate_
                .equals(other.unwrapTemplate_));
    }

    return equal;
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
   * Gets the check value attribute of this key.
   * 
   * @return The check value attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getCheckValue() {
    return checkValue_;
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

    // Object.getAttributeValue(session, objectHandle_, sensitive_);
    // Object.getAttributeValue(session, objectHandle_, encrypt_);
    // Object.getAttributeValue(session, objectHandle_, decrypt_);
    // Object.getAttributeValue(session, objectHandle_, sign_);
    // Object.getAttributeValue(session, objectHandle_, verify_);
    // Object.getAttributeValue(session, objectHandle_, wrap_);
    // Object.getAttributeValue(session, objectHandle_, unwrap_);
    // Object.getAttributeValue(session, objectHandle_, extractable_);
    // Object.getAttributeValue(session, objectHandle_, alwaysSensitive_);
    // Object.getAttributeValue(session, objectHandle_, neverExtractable_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { sensitive_,
        encrypt_, decrypt_, sign_, verify_, wrap_, unwrap_, extractable_,
        alwaysSensitive_, neverExtractable_, checkValue_, wrapWithTrusted_, trusted_ });
    Object.getAttributeValue(session, objectHandle_, wrapTemplate_);
    Object.getAttributeValue(session, objectHandle_, unwrapTemplate_);
    // Object.getAttributeValues(session, objectHandle_, new Attribute[] {
    // wrapTemplate_, unwrapTemplate_ });
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
    buffer.append("Sensitive: ");
    buffer.append(sensitive_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Encrypt: ");
    buffer.append(encrypt_.toString());

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
    buffer.append("Verify: ");
    buffer.append(verify_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap: ");
    buffer.append(wrap_.toString());

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
    buffer.append("Check Value: ");
    buffer.append(checkValue_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap With Trusted: ");
    buffer.append(wrapWithTrusted_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Trusted: ");
    buffer.append(trusted_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap Template: ");
    buffer.append(wrapTemplate_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Unwrap Template: ");
    buffer.append(unwrapTemplate_.toString());

    return buffer.toString();
  }

}
