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

import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.util.Hashtable;

/**
 * This is the base-class for all types of attributes. In general, all PKCS#11 objects are just a
 * collection of attributes. PKCS#11 specifies which attributes each type of objects must have. In
 * some cases, attributes are optinal (e.g. in RSAPrivateKey). In such a case, this attribute will
 * return false when the application calls isPresent() on this attribute. This measn, that the
 * object does not posses this attribute (maybe even though it should, but not all drivers seem to
 * implement the standard correctly). Handling attributes in this fashion ensures that this library
 * can work also with drivers that are not fully compliant. Moreover, certain attributes can be
 * sensitive; i.e. their values cannot be read, e.g. the private exponent of a RSA private key.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (ckAttribute_ <> null)
 */
public abstract class Attribute implements Cloneable {

  public static final Long CLASS = new Long(PKCS11Constants.CKA_CLASS);
  public static final Long TOKEN = new Long(PKCS11Constants.CKA_TOKEN);
  public static final Long PRIVATE = new Long(PKCS11Constants.CKA_PRIVATE);
  public static final Long LABEL = new Long(PKCS11Constants.CKA_LABEL);
  public static final Long APPLICATION = new Long(PKCS11Constants.CKA_APPLICATION);
  public static final Long VALUE = new Long(PKCS11Constants.CKA_VALUE);
  public static final Long OBJECT_ID = new Long(PKCS11Constants.CKA_OBJECT_ID);
  public static final Long CERTIFICATE_TYPE = new Long(
      PKCS11Constants.CKA_CERTIFICATE_TYPE);
  public static final Long ISSUER = new Long(PKCS11Constants.CKA_ISSUER);
  public static final Long SERIAL_NUMBER = new Long(PKCS11Constants.CKA_SERIAL_NUMBER);
  public static final Long URL = new Long(PKCS11Constants.CKA_URL);
  public static final Long HASH_OF_SUBJECT_PUBLIC_KEY = new Long(
      PKCS11Constants.CKA_HASH_OF_SUBJECT_PUBLIC_KEY);
  public static final Long HASH_OF_ISSUER_PUBLIC_KEY = new Long(
      PKCS11Constants.CKA_HASH_OF_ISSUER_PUBLIC_KEY);
  public static final Long JAVA_MIDP_SECURITY_DOMAIN = new Long(
      PKCS11Constants.CKA_JAVA_MIDP_SECURITY_DOMAIN);
  public static final Long AC_ISSUER = new Long(PKCS11Constants.CKA_AC_ISSUER);
  public static final Long OWNER = new Long(PKCS11Constants.CKA_OWNER);
  public static final Long ATTR_TYPES = new Long(PKCS11Constants.CKA_ATTR_TYPES);
  public static final Long TRUSTED = new Long(PKCS11Constants.CKA_TRUSTED);
  public static final Long KEY_TYPE = new Long(PKCS11Constants.CKA_KEY_TYPE);
  public static final Long SUBJECT = new Long(PKCS11Constants.CKA_SUBJECT);
  public static final Long ID = new Long(PKCS11Constants.CKA_ID);
  public static final Long CHECK_VALUE = new Long(PKCS11Constants.CKA_CHECK_VALUE);
  public static final Long CERTIFICATE_CATEGORY = new Long(
      PKCS11Constants.CKA_CERTIFICATE_CATEGORY);
  public static final Long SENSITIVE = new Long(PKCS11Constants.CKA_SENSITIVE);
  public static final Long ENCRYPT = new Long(PKCS11Constants.CKA_ENCRYPT);
  public static final Long DECRYPT = new Long(PKCS11Constants.CKA_DECRYPT);
  public static final Long WRAP = new Long(PKCS11Constants.CKA_WRAP);
  public static final Long WRAP_TEMPLATE = new Long(PKCS11Constants.CKA_WRAP_TEMPLATE);
  public static final Long UNWRAP = new Long(PKCS11Constants.CKA_UNWRAP);
  public static final Long UNWRAP_TEMPLATE = new Long(PKCS11Constants.CKA_UNWRAP_TEMPLATE);
  public static final Long SIGN = new Long(PKCS11Constants.CKA_SIGN);
  public static final Long SIGN_RECOVER = new Long(PKCS11Constants.CKA_SIGN_RECOVER);
  public static final Long VERIFY = new Long(PKCS11Constants.CKA_VERIFY);
  public static final Long VERIFY_RECOVER = new Long(PKCS11Constants.CKA_VERIFY_RECOVER);
  public static final Long DERIVE = new Long(PKCS11Constants.CKA_DERIVE);
  public static final Long START_DATE = new Long(PKCS11Constants.CKA_START_DATE);
  public static final Long END_DATE = new Long(PKCS11Constants.CKA_END_DATE);
  public static final Long MECHANISM_TYPE = new Long(PKCS11Constants.CKA_MECHANISM_TYPE);
  public static final Long MODULUS = new Long(PKCS11Constants.CKA_MODULUS);
  public static final Long MODULUS_BITS = new Long(PKCS11Constants.CKA_MODULUS_BITS);
  public static final Long PUBLIC_EXPONENT = new Long(PKCS11Constants.CKA_PUBLIC_EXPONENT);
  public static final Long PRIVATE_EXPONENT = new Long(
      PKCS11Constants.CKA_PRIVATE_EXPONENT);
  public static final Long PRIME_1 = new Long(PKCS11Constants.CKA_PRIME_1);
  public static final Long PRIME_2 = new Long(PKCS11Constants.CKA_PRIME_2);
  public static final Long EXPONENT_1 = new Long(PKCS11Constants.CKA_EXPONENT_1);
  public static final Long EXPONENT_2 = new Long(PKCS11Constants.CKA_EXPONENT_2);
  public static final Long COEFFICIENT = new Long(PKCS11Constants.CKA_COEFFICIENT);
  public static final Long PRIME = new Long(PKCS11Constants.CKA_PRIME);
  public static final Long SUBPRIME = new Long(PKCS11Constants.CKA_SUBPRIME);
  public static final Long BASE = new Long(PKCS11Constants.CKA_BASE);
  public static final Long PRIME_BITS = new Long(PKCS11Constants.CKA_PRIME_BITS);
  public static final Long SUB_PRIME_BITS = new Long(PKCS11Constants.CKA_SUB_PRIME_BITS);
  public static final Long VALUE_BITS = new Long(PKCS11Constants.CKA_VALUE_BITS);
  public static final Long VALUE_LEN = new Long(PKCS11Constants.CKA_VALUE_LEN);
  public static final Long EXTRACTABLE = new Long(PKCS11Constants.CKA_EXTRACTABLE);
  public static final Long LOCAL = new Long(PKCS11Constants.CKA_LOCAL);
  public static final Long NEVER_EXTRACTABLE = new Long(
      PKCS11Constants.CKA_NEVER_EXTRACTABLE);
  public static final Long WRAP_WITH_TRUSTED = new Long(
      PKCS11Constants.CKA_WRAP_WITH_TRUSTED);
  public static final Long ALWAYS_SENSITIVE = new Long(
      PKCS11Constants.CKA_ALWAYS_SENSITIVE);
  public static final Long ALWAYS_AUTHENTICATE = new Long(
      PKCS11Constants.CKA_ALWAYS_AUTHENTICATE);
  public static final Long KEY_GEN_MECHANISM = new Long(
      PKCS11Constants.CKA_KEY_GEN_MECHANISM);
  public static final Long ALLOWED_MECHANISMS = new Long(
      PKCS11Constants.CKA_ALLOWED_MECHANISMS);
  public static final Long MODIFIABLE = new Long(PKCS11Constants.CKA_MODIFIABLE);
  public static final Long ECDSA_PARAMS = new Long(PKCS11Constants.CKA_ECDSA_PARAMS);
  public static final Long EC_PARAMS = new Long(PKCS11Constants.CKA_EC_PARAMS);
  public static final Long EC_POINT = new Long(PKCS11Constants.CKA_EC_POINT);
  public static final Long SECONDARY_AUTH = new Long(PKCS11Constants.CKA_SECONDARY_AUTH);
  public static final Long AUTH_PIN_FLAGS = new Long(PKCS11Constants.CKA_AUTH_PIN_FLAGS);
  public static final Long HW_FEATURE_TYPE = new Long(PKCS11Constants.CKA_HW_FEATURE_TYPE);
  public static final Long RESET_ON_INIT = new Long(PKCS11Constants.CKA_RESET_ON_INIT);
  public static final Long HAS_RESET = new Long(PKCS11Constants.CKA_HAS_RESET);
  public static final Long VENDOR_DEFINED = new Long(PKCS11Constants.CKA_VENDOR_DEFINED);
  public static final Long PIXEL_X = new Long(PKCS11Constants.CKA_PIXEL_X);
  public static final Long PIXEL_Y = new Long(PKCS11Constants.CKA_PIXEL_Y);
  public static final Long RESOLUTION = new Long(PKCS11Constants.CKA_RESOLUTION);
  public static final Long CHAR_ROWS = new Long(PKCS11Constants.CKA_CHAR_ROWS);
  public static final Long CHAR_COLUMNS = new Long(PKCS11Constants.CKA_CHAR_COLUMNS);
  public static final Long COLOR = new Long(PKCS11Constants.CKA_COLOR);
  public static final Long BITS_PER_PIXEL = new Long(PKCS11Constants.CKA_BITS_PER_PIXEL);
  public static final Long CHAR_SETS = new Long(PKCS11Constants.CKA_CHAR_SETS);
  public static final Long ENCODING_METHODS = new Long(
      PKCS11Constants.CKA_ENCODING_METHODS);
  public static final Long MIME_TYPES = new Long(PKCS11Constants.CKA_MIME_TYPES);

  protected static Hashtable attributeNames_;
  protected static Hashtable attributeClasses_;

  /**
   * True, if the object really posesses this attribute.
   */
  protected boolean present_;

  /**
   * True, if this attribute is sensitive.
   */
  protected boolean sensitive_;

  /**
   * The CK_ATTRIBUTE that is used to hold the PKCS#11 type of this attribute and the value.
   */
  protected CK_ATTRIBUTE ckAttribute_;

  /**
   * Empty constructor. Attention! If you use this constructor, you must set ckAttribute_ to ensure
   * that the class invariant is not violated.
   * 
   */
  protected Attribute() { /* left empty intentionally */
  }

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   * 
   * @param type
   *          The PKCS'11 type of this attribute; e.g. PKCS11Constants.CKA_PRIVATE.
   * @preconditions (type <> null)
   * 
   */
  protected Attribute(Long type) {
    if (type == null) {
      throw new NullPointerException("Argument \"type\" must not be null.");
    }

    present_ = false;
    sensitive_ = false;
    ckAttribute_ = new CK_ATTRIBUTE();
    ckAttribute_.type = type.longValue();
  }

  /**
   * Get the name of the given attribute type.
   * 
   * @param type
   *          The attribute type.
   * @return The name of the attribute type, or null if there is no such type.
   */
  protected synchronized static String getAttributeName(Long type) {
    if (type == null) {
      throw new NullPointerException("Argument \"type\" must not be null.");
    }

    if (attributeNames_ == null) {
      attributeNames_ = new Hashtable(85);
      attributeNames_.put(Attribute.CLASS, "Class");
      attributeNames_.put(Attribute.TOKEN, "Token");
      attributeNames_.put(Attribute.PRIVATE, "Private");
      attributeNames_.put(Attribute.LABEL, "Label");
      attributeNames_.put(Attribute.APPLICATION, "Application");
      attributeNames_.put(Attribute.VALUE, "Value");
      attributeNames_.put(Attribute.OBJECT_ID, "Object ID");
      attributeNames_.put(Attribute.CERTIFICATE_TYPE, "Certificate Type");
      attributeNames_.put(Attribute.ISSUER, "Issuer");
      attributeNames_.put(Attribute.SERIAL_NUMBER, "Serial Number");
      attributeNames_.put(Attribute.URL, "URL");
      attributeNames_.put(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY,
          "Hash Of Subject Public Key");
      attributeNames_.put(Attribute.HASH_OF_ISSUER_PUBLIC_KEY,
          "Hash Of Issuer Public Key");
      attributeNames_.put(Attribute.JAVA_MIDP_SECURITY_DOMAIN,
          "Java MIDP Security Domain");
      attributeNames_.put(Attribute.AC_ISSUER, "AC Issuer");
      attributeNames_.put(Attribute.OWNER, "Owner");
      attributeNames_.put(Attribute.ATTR_TYPES, "Attribute Types");
      attributeNames_.put(Attribute.TRUSTED, "Trusted");
      attributeNames_.put(Attribute.KEY_TYPE, "Key Type");
      attributeNames_.put(Attribute.SUBJECT, "Subject");
      attributeNames_.put(Attribute.ID, "ID");
      attributeNames_.put(Attribute.CHECK_VALUE, "Check Value");
      attributeNames_.put(Attribute.CERTIFICATE_CATEGORY, "Certificate Category");
      attributeNames_.put(Attribute.SENSITIVE, "Sensitive");
      attributeNames_.put(Attribute.ENCRYPT, "Encrypt");
      attributeNames_.put(Attribute.DECRYPT, "Decrypt");
      attributeNames_.put(Attribute.WRAP, "Wrap");
      attributeNames_.put(Attribute.UNWRAP, "Unwrap");
      attributeNames_.put(Attribute.WRAP_TEMPLATE, "Wrap Template");
      attributeNames_.put(Attribute.UNWRAP_TEMPLATE, "Unwrap Template");
      attributeNames_.put(Attribute.SIGN, "Sign");
      attributeNames_.put(Attribute.SIGN_RECOVER, "Sign Recover");
      attributeNames_.put(Attribute.VERIFY, "Verify");
      attributeNames_.put(Attribute.VERIFY_RECOVER, "Verify Recover");
      attributeNames_.put(Attribute.DERIVE, "Derive");
      attributeNames_.put(Attribute.START_DATE, "Start Date");
      attributeNames_.put(Attribute.END_DATE, "End Date");
      attributeNames_.put(Attribute.MODULUS, "Modulus");
      attributeNames_.put(Attribute.MODULUS_BITS, "Modulus Bits");
      attributeNames_.put(Attribute.PUBLIC_EXPONENT, "Public Exponent");
      attributeNames_.put(Attribute.PRIVATE_EXPONENT, "Private Exponent");
      attributeNames_.put(Attribute.PRIME_1, "Prime 1");
      attributeNames_.put(Attribute.PRIME_2, "Prime 2");
      attributeNames_.put(Attribute.EXPONENT_1, "Exponent 1");
      attributeNames_.put(Attribute.EXPONENT_2, "Exponent 2");
      attributeNames_.put(Attribute.COEFFICIENT, "Coefficient");
      attributeNames_.put(Attribute.PRIME, "Prime");
      attributeNames_.put(Attribute.SUBPRIME, "Subprime");
      attributeNames_.put(Attribute.BASE, "Base");
      attributeNames_.put(Attribute.PRIME_BITS, "Prime Pits");
      attributeNames_.put(Attribute.SUB_PRIME_BITS, "Subprime Bits");
      attributeNames_.put(Attribute.VALUE_BITS, "Value Bits");
      attributeNames_.put(Attribute.VALUE_LEN, "Value Length");
      attributeNames_.put(Attribute.EXTRACTABLE, "Extractable");
      attributeNames_.put(Attribute.LOCAL, "Local");
      attributeNames_.put(Attribute.NEVER_EXTRACTABLE, "Never Extractable");
      attributeNames_.put(Attribute.WRAP_WITH_TRUSTED, "Wrap With Trusted");
      attributeNames_.put(Attribute.ALWAYS_SENSITIVE, "Always Sensitive");
      attributeNames_.put(Attribute.ALWAYS_AUTHENTICATE, "Always Authenticate");
      attributeNames_.put(Attribute.KEY_GEN_MECHANISM, "Key Generation Mechanism");
      attributeNames_.put(Attribute.ALLOWED_MECHANISMS, "Allowed Mechanisms");
      attributeNames_.put(Attribute.MODIFIABLE, "Modifiable");
      attributeNames_.put(Attribute.ECDSA_PARAMS, "ECDSA Parameters");
      attributeNames_.put(Attribute.EC_PARAMS, "EC Parameters");
      attributeNames_.put(Attribute.EC_POINT, "EC Point");
      attributeNames_.put(Attribute.SECONDARY_AUTH, "Secondary Authentication");
      attributeNames_.put(Attribute.AUTH_PIN_FLAGS, "Authentication PIN Flags");
      attributeNames_.put(Attribute.HW_FEATURE_TYPE, "Hardware Feature Type");
      attributeNames_.put(Attribute.RESET_ON_INIT, "Reset on Initialization");
      attributeNames_.put(Attribute.HAS_RESET, "Has been reset");
      attributeNames_.put(Attribute.VENDOR_DEFINED, "Vendor Defined");
    }

    String name;

    if ((type.longValue() & Attribute.VENDOR_DEFINED.longValue()) != 0L) {
      StringBuffer nameBuffer = new StringBuffer(36);
      nameBuffer.append("VENDOR_DEFINED [0x");
      nameBuffer.append(Long.toHexString(type.longValue()));
      nameBuffer.append(']');
      name = nameBuffer.toString();
    } else {
      name = (String) attributeNames_.get(type);
      if (name == null) {
        StringBuffer nameBuffer = new StringBuffer(25);
        nameBuffer.append("[0x");
        nameBuffer.append(Long.toHexString(type.longValue()));
        nameBuffer.append(']');
        name = nameBuffer.toString();
      }
    }

    return name;
  }

  /**
   * Get the class of the given attribute type. Current existing Attribute classes are:
   * AttributeArray BooleanAttribute ByteArrayAttribute CertificateTypeAttribute CharArrayAttribute
   * DateAttribute HardwareFeatureTypeAttribute KeyTypeAttribute LongAttribute MechanismAttribute
   * MechanismArrayAttribute ObjectClassAttribute
   * 
   * @param type
   *          The attribute type.
   * @return The class of the attribute type, or null if there is no such type.
   */
  protected synchronized static Class getAttributeClass(Long type) {
    if (type == null) {
      throw new NullPointerException("Argument \"type\" must not be null.");
    }

    if (attributeClasses_ == null) {
      attributeClasses_ = new Hashtable(85);
      attributeClasses_.put(Attribute.CLASS, ObjectClassAttribute.class); // CK_OBJECT_CLASS
      attributeClasses_.put(Attribute.TOKEN, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.PRIVATE, BooleanAttribute.class);// CK_BBOOL
      attributeClasses_.put(Attribute.LABEL, CharArrayAttribute.class); // RFC2279 string
      attributeClasses_.put(Attribute.APPLICATION, CharArrayAttribute.class); // RFC2279 string
      attributeClasses_.put(Attribute.VALUE, ByteArrayAttribute.class); // Byte Array
      attributeClasses_.put(Attribute.OBJECT_ID, ByteArrayAttribute.class); // Byte Array
      attributeClasses_.put(Attribute.CERTIFICATE_TYPE, CertificateTypeAttribute.class); // CK_CERTIFICATE_TYPE
      attributeClasses_.put(Attribute.ISSUER, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.SERIAL_NUMBER, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.URL, CharArrayAttribute.class); // RFC2279 string
      attributeClasses_.put(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY,
          ByteArrayAttribute.class); // Byte array
      attributeClasses_
          .put(Attribute.HASH_OF_ISSUER_PUBLIC_KEY, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.JAVA_MIDP_SECURITY_DOMAIN, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.AC_ISSUER, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.OWNER, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.ATTR_TYPES, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.TRUSTED, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.KEY_TYPE, KeyTypeAttribute.class); // CK_KEY_TYPE
      attributeClasses_.put(Attribute.SUBJECT, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.ID, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.CHECK_VALUE, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.CERTIFICATE_CATEGORY, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.SENSITIVE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.ENCRYPT, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.DECRYPT, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.WRAP, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.UNWRAP, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.WRAP_TEMPLATE, AttributeArray.class); // CK_ATTRIBUTE_PTR
      attributeClasses_.put(Attribute.UNWRAP_TEMPLATE, AttributeArray.class); // CK_ATTRIBUTE_PTR
      attributeClasses_.put(Attribute.SIGN, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.SIGN_RECOVER, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.VERIFY, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.VERIFY_RECOVER, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.DERIVE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.START_DATE, DateAttribute.class); // CK_DATE
      attributeClasses_.put(Attribute.END_DATE, DateAttribute.class); // CK_DATE
      attributeClasses_.put(Attribute.MODULUS, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.MODULUS_BITS, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.PUBLIC_EXPONENT, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.PRIVATE_EXPONENT, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.PRIME_1, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.PRIME_2, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.EXPONENT_1, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.EXPONENT_2, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.COEFFICIENT, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.PRIME, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.SUBPRIME, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.BASE, ByteArrayAttribute.class); // Big integer
      attributeClasses_.put(Attribute.PRIME_BITS, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.SUB_PRIME_BITS, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.VALUE_BITS, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.VALUE_LEN, LongAttribute.class); // CK_ULONG
      attributeClasses_.put(Attribute.EXTRACTABLE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.LOCAL, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.NEVER_EXTRACTABLE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.WRAP_WITH_TRUSTED, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.ALWAYS_SENSITIVE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.ALWAYS_AUTHENTICATE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.KEY_GEN_MECHANISM, MechanismAttribute.class); // CK_MECHANISM_TYPE
      attributeClasses_.put(Attribute.ALLOWED_MECHANISMS, MechanismArrayAttribute.class); // CK_MECHANISM_TYPE_PTR
      attributeClasses_.put(Attribute.MODIFIABLE, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.ECDSA_PARAMS, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.EC_PARAMS, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.EC_POINT, ByteArrayAttribute.class); // Byte array
      attributeClasses_.put(Attribute.SECONDARY_AUTH, BooleanAttribute.class); // CK_BBOOL -
                                                                               // deprecated
      attributeClasses_.put(Attribute.AUTH_PIN_FLAGS, LongAttribute.class); // CK_ULONG - deprecated
      attributeClasses_
          .put(Attribute.HW_FEATURE_TYPE, HardwareFeatureTypeAttribute.class); // CK_HW_FEATURE
      attributeClasses_.put(Attribute.RESET_ON_INIT, BooleanAttribute.class); // CK_BBOOL
      attributeClasses_.put(Attribute.HAS_RESET, BooleanAttribute.class); // CK_BBOOL
    }

    Class implementation = (Class) attributeClasses_.get(type);
    return implementation;

  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof Attribute) and (result.equals(this))
   */
  public java.lang.Object clone() {
    Attribute clone;

    try {
      clone = (Attribute) super.clone();
      clone.ckAttribute_ = (CK_ATTRIBUTE) this.ckAttribute_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Set, if this attribute is really present in the associated object. Does only make sense if used
   * in combination with template objects.
   * 
   * @param present
   *          True, if attribute is present.
   */
  public void setPresent(boolean present) {
    present_ = present;
  }

  /**
   * Set, if this attribute is sensitive in the associated object. Does only make sense if used in
   * combination with template objects.
   * 
   * @param sensitive
   *          True, if attribute is sensitive.
   */
  public void setSensitive(boolean sensitive) {
    sensitive_ = sensitive;
  }

  /**
   * Redirects the request for setting the attribute value to the implementing attribute class.
   * 
   * @param value
   *          the new value
   * @throws ClassCastException
   *           the given value type is not valid for this very {@link Attribute}.
   * @throws UnsupportedOperationException
   *           the {@link OtherAttribute} implementation does not support setting a value directly.
   */
  abstract public void setValue(java.lang.Object value)
      throws UnsupportedOperationException;

  /**
   * Set the CK_ATTRIBUTE of this Attribute. Only for internal use.
   * 
   * @param ckAttribute
   *          The new CK_ATTRIBUTE of this Attribute.
   * @preconditions (ckAttribute <> null)
   * 
   */
  protected void setCkAttribute(CK_ATTRIBUTE ckAttribute) {
    if (ckAttribute == null) {
      throw new NullPointerException("Argument \"ckAttribute\" must not be null.");
    }
    ckAttribute_ = ckAttribute;
  }

  /**
   * Check, if this attribute is really present in the associated object.
   * 
   * @return True, if this attribute is really present in the associated object.
   */
  public boolean isPresent() {
    return present_;
  }

  /**
   * Check, if this attribute is sensitive in the associated object.
   * 
   * @return True, if this attribute is sensitive in the associated object.
   */
  public boolean isSensitive() {
    return sensitive_;
  }

  /**
   * Get the CK_ATTRIBUTE object of this Attribute that contains the attribute type and value .
   * 
   * @return The CK_ATTRIBUTE of this Attribute.
   * 
   * @postconditions (result <> null)
   */
  protected CK_ATTRIBUTE getCkAttribute() {
    return ckAttribute_;
  }

  /**
   * Get a string representation of the value of this attribute.
   * 
   * @return A string representation of the value of this attribute.
   * 
   * @postconditions (result <> null)
   */
  protected String getValueString() {
    String valueString;

    if ((ckAttribute_ != null) && (ckAttribute_.pValue != null)) {
      valueString = ckAttribute_.pValue.toString();
    } else {
      valueString = "<NULL_PTR>";
    }

    return valueString;
  }

  /**
   * Get a string representation of this attribute. If the attribute is not present or if it is
   * sensitive, the output of this method shows jsut a message telling this. This string does not
   * contain the attribute's type name.
   * 
   * @return A string representation of the value of this attribute.
   * 
   * @postconditions (result <> null)
   */
  public String toString() {
    return toString(false);
  }

  /**
   * Get a string representation of this attribute. If the attribute is not present or if it is
   * sensitive, the output of this method shows jsut a message telling this.
   * 
   * @param withName
   *          If true, the string contains the attribute type name and the value. If false, it just
   *          contains the value.
   * @return A string representation of this attribute.
   * 
   * @postconditions (result <> null)
   */
  public String toString(boolean withName) {
    StringBuffer buffer = new StringBuffer(32);

    if (withName) {
      String typeName = getAttributeName(new Long(ckAttribute_.type));
      buffer.append(typeName);
      buffer.append(": ");
    }
    if (present_) {
      if (sensitive_) {
        buffer.append("<Value is sensitive>");
      } else {
        buffer.append(getValueString());
      }
    } else {
      buffer.append("<Attribute not present>");
    }

    return buffer.toString();
  }

  /**
   * Set the PKCS#11 type of this attribute.
   * 
   * @param type
   *          The PKCS#11 type of this attribute.
   * @preconditions (type <> null)
   * 
   */
  protected void setType(Long type) {
    if (type == null) {
      throw new NullPointerException("Argument \"type\" must not be null.");
    }

    ckAttribute_.type = type.longValue();
  }

  /**
   * Get the PKCS#11 type of this attribute.
   * 
   * @return The PKCS#11 type of this attribute.
   * 
   * @postconditions (result <> null)
   */
  protected Long getType() {
    return new Long(ckAttribute_.type);
  }

  /**
   * True, if both attributes are not present or if both attributes are present and all other member
   * variables are equal. False, otherwise.
   * 
   * @param otherObject
   *          The other object to compare to.
   * @return True, if both attributes are not present or if both attributes are present and all
   *         other member variables are equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof Attribute) {
      Attribute other = (Attribute) otherObject;
      equal = (this == other)
          || (((this.present_ == false) && (other.present_ == false)) || (((this.present_ == true) && (other.present_ == true)) && ((this.sensitive_ == other.sensitive_)
              && (this.ckAttribute_.type == other.ckAttribute_.type) && ((this.ckAttribute_.pValue == other.ckAttribute_.pValue) || ((this.ckAttribute_.pValue != null) && this.ckAttribute_.pValue
              .equals(other.ckAttribute_.pValue))))));
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
    return ((int) ckAttribute_.type)
        ^ ((ckAttribute_.pValue != null) ? ckAttribute_.pValue.hashCode() : 0);
  }

}
