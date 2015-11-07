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

import java.util.Hashtable;

/**
 * An object of this class represents a key as defined by PKCS#11 2.11. A key is of a specific type:
 * RSA, DSA, DH, ECDSA, EC, X9_42_DH, KEA, GENERIC_SECRET, RC2, RC4, DES, DES2, DES3, CAST, CAST3,
 * CAST5, CAST128, RC5, IDEA, SKIPJACK, BATON, JUNIPER, CDMF, AES or VENDOR_DEFINED. If an
 * application needs to use vendor-defined keys, it must set a VendorDefinedKeyeBuilder using the
 * setVendorDefinedKeyBuilder method.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (keyType_ <> null) and (id_ <> null) and (startDate_ <> null) and (endDate_ <> null)
 *             and (derive_ <> null) and (local_ <> null) and (keyGenMechanism_ <> null)
 */
public class Key extends Storage {

  /**
   * This interface defines the available key types as defined by PKCS#11 2.11: RSA, DSA, DH, ECDSA,
   * KEA, GENERIC_SECRET, RC2, RC4, DES, DES2, DES3, CAST, CAST3, CAST5, CAST128, RC5, IDEA,
   * SKIPJACK, BATON, JUNIPER, CDMF, AES, EC, X9_42_DH or VENDOR_DEFINED.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface KeyType {

    /**
     * The identifier for a RSA key.
     */
    static public final Long RSA = new Long(PKCS11Constants.CKK_RSA);

    /**
     * The identifier for a DSA key.
     */
    static public final Long DSA = new Long(PKCS11Constants.CKK_DSA);

    /**
     * The identifier for a Diffi-Hellman key.
     */
    static public final Long DH = new Long(PKCS11Constants.CKK_DH);

    /**
     * The identifier for a ECDSA key.
     */
    static public final Long ECDSA = new Long(PKCS11Constants.CKK_ECDSA);

    /**
     * The identifier for a EC key.
     */
    static public final Long EC = new Long(PKCS11Constants.CKK_EC);

    /**
     * The identifier for a EC key.
     */
    static public final Long X9_42_DH = new Long(PKCS11Constants.CKK_X9_42_DH);

    /**
     * The identifier for a KEA key.
     */
    static public final Long KEA = new Long(PKCS11Constants.CKK_KEA);

    /**
     * The identifier for a generic secret key.
     */
    static public final Long GENERIC_SECRET = new Long(PKCS11Constants.CKK_GENERIC_SECRET);

    /**
     * The identifier for a RC2 key.
     */
    static public final Long RC2 = new Long(PKCS11Constants.CKK_RC2);

    /**
     * The identifier for a RC4 key.
     */
    static public final Long RC4 = new Long(PKCS11Constants.CKK_RC4);

    /**
     * The identifier for a DES key.
     */
    static public final Long DES = new Long(PKCS11Constants.CKK_DES);

    /**
     * The identifier for a double-length DES key.
     */
    static public final Long DES2 = new Long(PKCS11Constants.CKK_DES2);

    /**
     * The identifier for a trible-length DES key (Trible-DES).
     */
    static public final Long DES3 = new Long(PKCS11Constants.CKK_DES3);

    /**
     * The identifier for a CAST key.
     */
    static public final Long CAST = new Long(PKCS11Constants.CKK_CAST);

    /**
     * The identifier for a CAST3 key.
     */
    static public final Long CAST3 = new Long(PKCS11Constants.CKK_CAST3);

    /**
     * The identifier for a CAST5 key; CAST5 is the same as CAST128.
     */
    static public final Long CAST5 = new Long(PKCS11Constants.CKK_CAST5);

    /**
     * The identifier for a CAST128 key.
     */
    static public final Long CAST128 = new Long(PKCS11Constants.CKK_CAST128);

    /**
     * The identifier for a RC5 key.
     */
    static public final Long RC5 = new Long(PKCS11Constants.CKK_RC5);

    /**
     * The identifier for a IDEA key.
     */
    static public final Long IDEA = new Long(PKCS11Constants.CKK_IDEA);

    /**
     * The identifier for a SKIPJACK key.
     */
    static public final Long SKIPJACK = new Long(PKCS11Constants.CKK_SKIPJACK);

    /**
     * The identifier for a BATON key.
     */
    static public final Long BATON = new Long(PKCS11Constants.CKK_BATON);

    /**
     * The identifier for a JUNIPER key.
     */
    static public final Long JUNIPER = new Long(PKCS11Constants.CKK_JUNIPER);

    /**
     * The identifier for a CDMF key.
     */
    static public final Long CDMF = new Long(PKCS11Constants.CKK_CDMF);

    /**
     * The identifier for a AES key.
     */
    static public final Long AES = new Long(PKCS11Constants.CKK_AES);

    /**
     * The identifier for a Blowfish key.
     */
    static public final Long BLOWFISH = new Long(PKCS11Constants.CKK_BLOWFISH);

    /**
     * The identifier for a Twofish key.
     */
    static public final Long TWOFISH = new Long(PKCS11Constants.CKK_TWOFISH);

    /**
     * The identifier for a VENDOR_DEFINED key. Any Long object with a value bigger than this one is
     * also a valid vendor-defined key type identifier.
     */
    static public final Long VENDOR_DEFINED = new Long(PKCS11Constants.CKK_VENDOR_DEFINED);

  }

  /**
   * If an application uses vendor defined keys, it must implement this interface and install such
   * an object handler using setVendorDefinedKeyBuilder.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface VendorDefinedKeyBuilder {

    /**
     * This method should instanciate an Object of this class or of any sub-class. It can use the
     * given handles and PKCS#11 module to retrieve attributes of the PKCS#11 object from the token.
     * 
     * @param session
     *          The session to use for reading attributes. This session must have the appropriate
     *          rights; i.e. it must be a user-session, if it is a private object.
     * @param objectHandle
     *          The object handle as given from the PKCS#111 module.
     * @return The object representing the PKCS#11 object. The returned object can be casted to the
     *         according sub-class.
     * @exception PKCS11Exception
     *              If getting the attributes failed.
     * @preconditions (session <> null)
     * @postconditions (result <> null)
     */
    public Object build(Session session, long objectHandle) throws PKCS11Exception;

  }

  /**
   * The currently set vendor defined key builder, or null.
   */
  protected static VendorDefinedKeyBuilder vendorKeyBuilder_;

  /**
   * A table holding string representations for all known key types. Table key is the key type as
   * Long object.
   */
  protected static Hashtable keyTypeNames_;

  /**
   * The type of this key. Its value is one of KeyType, or one that has a bigger value than
   * VENDOR_DEFINED.
   */
  protected KeyTypeAttribute keyType_;

  /**
   * The identifier (ID) of this key.
   */
  protected ByteArrayAttribute id_;

  /**
   * The start date of this key's validity.
   */
  protected DateAttribute startDate_;

  /**
   * The end date of this key's validity.
   */
  protected DateAttribute endDate_;

  /**
   * True, if other keys can be derived from this key.
   */
  protected BooleanAttribute derive_;

  /**
   * True, if this key was created (generated or copied from a different key) on the token.
   */
  protected BooleanAttribute local_;

  /**
   * The mechanism used to generate the key material.
   */
  protected MechanismAttribute keyGenMechanism_;

  /**
   * The list of mechanism that can be used with this key.
   */
  protected MechanismArrayAttribute allowedMechanisms_;

  /**
   * The default constructor. An application use this constructor to instanciate a key that serves
   * as a template. It may also be useful for working with vendor-defined keys.
   * 
   */
  public Key() {
    super();
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 key.
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
  protected Key(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
  }

  /**
   * Set a vendor-defined key builder that should be called to create an instance of an
   * vendor-defined PKCS#11 key; i.e. an instance of a vendor defined sub-class of this class.
   * 
   * @param builder
   *          The vendor-defined key builder. Null to clear any previously installed vendor-defined
   *          builder.
   */
  public static void setVendorDefinedKeyBuilder(VendorDefinedKeyBuilder builder) {
    vendorKeyBuilder_ = builder;
  }

  /**
   * Get the currently set vendor-defined key builder.
   * 
   * @return The currently set vendor-defined key builder or null if none is set.
   */
  public static VendorDefinedKeyBuilder getVendorDefinedKeyBuilder() {
    return vendorKeyBuilder_;
  }

  /**
   * Get the given key type as string.
   * 
   * @param keyType
   *          The key type to get as string.
   * @return A string denoting the key type; e.g. "RSA".
   * @preconditions (keyType <> null)
   * @postconditions (result <> null)
   */
  public static String getKeyTypeName(Long keyType) {
    String keyTypeName;

    if (keyType == null) {
      throw new NullPointerException("Argument \"keyType\" must not be null.");
    }

    if ((keyType.longValue() & PKCS11Constants.CKK_VENDOR_DEFINED) != 0L) {
      keyTypeName = "Vendor Defined";
    } else {
      if (keyTypeNames_ == null) {
        // setup key type names table
        Hashtable keyTypeNames = new Hashtable(24);
        keyTypeNames.put(KeyType.RSA, "RSA");
        keyTypeNames.put(KeyType.DSA, "DSA");
        keyTypeNames.put(KeyType.DH, "DH");
        keyTypeNames.put(KeyType.ECDSA, "ECDSA");
        keyTypeNames.put(KeyType.EC, "EC");
        keyTypeNames.put(KeyType.X9_42_DH, "X9_42_DH");
        keyTypeNames.put(KeyType.KEA, "KEA");
        keyTypeNames.put(KeyType.GENERIC_SECRET, "GENERIC_SECRET");
        keyTypeNames.put(KeyType.RC2, "RC2");
        keyTypeNames.put(KeyType.RC4, "RC4");
        keyTypeNames.put(KeyType.DES, "DES");
        keyTypeNames.put(KeyType.DES2, "DES2");
        keyTypeNames.put(KeyType.DES3, "DES3");
        keyTypeNames.put(KeyType.CAST, "CAST");
        keyTypeNames.put(KeyType.CAST3, "CAST3");
        keyTypeNames.put(KeyType.CAST5, "CAST5");
        keyTypeNames.put(KeyType.CAST128, "CAST128");
        keyTypeNames.put(KeyType.RC5, "RC5");
        keyTypeNames.put(KeyType.IDEA, "IDEA");
        keyTypeNames.put(KeyType.SKIPJACK, "SKIPJACK");
        keyTypeNames.put(KeyType.BATON, "BATON");
        keyTypeNames.put(KeyType.JUNIPER, "JUNIPER");
        keyTypeNames.put(KeyType.CDMF, "CDMF");
        keyTypeNames.put(KeyType.AES, "AES");
        keyTypeNames.put(KeyType.BLOWFISH, "BLOWFISH");
        keyTypeNames.put(KeyType.TWOFISH, "TWOFISH");
        keyTypeNames_ = keyTypeNames;
      }

      keyTypeName = (String) keyTypeNames_.get(keyType);
      if (keyTypeName == null) {
        keyTypeName = "<unknown>";
      }
    }

    return keyTypeName;
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
  protected static void putAttributesInTable(Key object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.KEY_TYPE, object.keyType_);
    object.attributeTable_.put(Attribute.ID, object.id_);
    object.attributeTable_.put(Attribute.START_DATE, object.startDate_);
    object.attributeTable_.put(Attribute.END_DATE, object.endDate_);
    object.attributeTable_.put(Attribute.DERIVE, object.derive_);
    object.attributeTable_.put(Attribute.LOCAL, object.local_);
    object.attributeTable_.put(Attribute.KEY_GEN_MECHANISM, object.keyGenMechanism_);
    object.attributeTable_.put(Attribute.ALLOWED_MECHANISMS, object.allowedMechanisms_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    keyType_ = new KeyTypeAttribute();
    id_ = new ByteArrayAttribute(Attribute.ID);
    startDate_ = new DateAttribute(Attribute.START_DATE);
    endDate_ = new DateAttribute(Attribute.END_DATE);
    derive_ = new BooleanAttribute(Attribute.DERIVE);
    local_ = new BooleanAttribute(Attribute.LOCAL);
    keyGenMechanism_ = new MechanismAttribute(Attribute.KEY_GEN_MECHANISM);
    allowedMechanisms_ = new MechanismArrayAttribute(Attribute.ALLOWED_MECHANISMS);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof Key) and (result.equals(this))
   */
  public java.lang.Object clone() {
    Key clone = (Key) super.clone();

    clone.keyType_ = (KeyTypeAttribute) this.keyType_.clone();
    clone.id_ = (ByteArrayAttribute) this.id_.clone();
    clone.startDate_ = (DateAttribute) this.startDate_.clone();
    clone.endDate_ = (DateAttribute) this.endDate_.clone();
    clone.derive_ = (BooleanAttribute) this.derive_.clone();
    clone.local_ = (BooleanAttribute) this.local_.clone();
    clone.keyGenMechanism_ = (MechanismAttribute) this.keyGenMechanism_.clone();
    clone.allowedMechanisms_ = (MechanismArrayAttribute) this.allowedMechanisms_.clone();

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

    if (otherObject instanceof Key) {
      Key other = (Key) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.keyType_.equals(other.keyType_)
              && this.id_.equals(other.id_) && this.startDate_.equals(other.startDate_)
              && this.endDate_.equals(other.endDate_)
              && this.derive_.equals(other.derive_) && this.local_.equals(other.local_)
              && this.keyGenMechanism_.equals(other.keyGenMechanism_) && this.allowedMechanisms_
                .equals(other.allowedMechanisms_));
    }

    return equal;
  }

  /**
   * Gets the key type attribute of the PKCS#11 key. Its value must be one of those defined in the
   * KeyType interface or one with an value bigger than KeyType.VENDOR_DEFINED.
   * 
   * @return The key type identifier.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getKeyType() {
    return keyType_;
  }

  /**
   * Gets the ID attribute of this key.
   * 
   * @return The key identifier attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getId() {
    return id_;
  }

  /**
   * Gets the start date attribute of the validity of this key.
   * 
   * @return The start date of validity.
   * 
   * @postconditions (result <> null)
   */
  public DateAttribute getStartDate() {
    return startDate_;
  }

  /**
   * Gets the end date attribute of the validity of this key.
   * 
   * @return The end date of validity.
   * 
   * @postconditions (result <> null)
   */
  public DateAttribute getEndDate() {
    return endDate_;
  }

  /**
   * Check, if other keys can be derived from this key.
   * 
   * @return Its value is true, if other keys can be derived from this key.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getDerive() {
    return derive_;
  }

  /**
   * Check, if this key is a local key; i.e. was generated on the token or created via copy from a
   * different key on the token.
   * 
   * @return Its value is true, if the key was created on the token.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getLocal() {
    return local_;
  }

  /**
   * Get the mechanism used to generate the key material for this key.
   * 
   * @return The mechanism attribute used to generate the key material for this key.
   * 
   * @postconditions (result <> null)
   */
  public MechanismAttribute getKeyGenMechanism() {
    return keyGenMechanism_;
  }

  /**
   * Get the list of mechanisms that are allowed to use with this key. This attribute can only be
   * used with PKCS#11 modules supporting cryptoki version 2.20 or higher.
   * 
   * @return The list of mechanisms that are allowed to use with this key.
   * 
   * @postconditions (result <> null)
   */
  public MechanismArrayAttribute getAllowedMechanisms() {
    return allowedMechanisms_;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return keyType_.hashCode() ^ id_.hashCode();
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

    // Object.getAttributeValue(session, objectHandle_, id_);
    // Object.getAttributeValue(session, objectHandle_, startDate_);
    // Object.getAttributeValue(session, objectHandle_, endDate_);
    // Object.getAttributeValue(session, objectHandle_, derive_);
    // Object.getAttributeValue(session, objectHandle_, local_);
    // Object.getAttributeValue(session, objectHandle_, keyGenMechanism_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { id_, startDate_,
        endDate_, derive_, local_, keyGenMechanism_ });
    Object.getAttributeValue(session, objectHandle_, allowedMechanisms_);
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
    buffer.append("Key Type: ");
    if (keyType_ != null) {
      buffer.append(keyType_.toString());
    } else {
      buffer.append("<unavailable>");
    }

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("ID: ");
    buffer.append(id_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Start Date: ");
    buffer.append(startDate_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("End Date: ");
    buffer.append(endDate_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Derive: ");
    buffer.append(derive_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Local: ");
    buffer.append(local_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Key Generation Mechanism: ");
    buffer.append(keyGenMechanism_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Allowed Mechanisms: ");
    buffer.append(allowedMechanisms_.toString());

    return buffer.toString();
  }

}
