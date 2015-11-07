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
 * An object of this class represents a certificate as defined by PKCS#11. A certificate is of a
 * specific type: X_509_PUBLIC_KEY, X_509_ATTRIBUTE or VENDOR_DEFINED. If an application needs to
 * use vendor-defined certificates, it must set a VendorDefinedCertificateBuilder using the
 * setVendorDefinedCertificateBuilder method.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (certificateType_ <> null) and (trusted_ <> null)
 */
public class Certificate extends Storage {

  /**
   * This interface defines the available certificate types as defined by PKCS#11: X_509_PUBLIC_KEY,
   * X_509_ATTRIBUTE or VENDOR_DEFINED.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface CertificateType {

    /**
     * The identifier for a X.509 public key certificate.
     */
    static public final Long X_509_PUBLIC_KEY = new Long(PKCS11Constants.CKC_X_509);

    /**
     * The identifier for a X.509 attribute certificate.
     */
    static public final Long X_509_ATTRIBUTE = new Long(
        PKCS11Constants.CKC_X_509_ATTR_CERT);

    /**
     * The identifier for a WTL certificate.
     */
    static public final Long WTLS = new Long(PKCS11Constants.CKC_WTLS);

    /**
     * The identifier for a vendor-defined certificate. Any Long object with a value bigger than
     * this one is also a valid vendor-defined certificate type identifier.
     */
    static public final Long VENDOR_DEFINED = new Long(PKCS11Constants.CKC_VENDOR_DEFINED);

  }

  /**
   * If an application uses vendor defined certificates, it must implement this interface and
   * install such an object handler using setVendorDefinedCertificateBuilder.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface VendorDefinedCertificateBuilder {

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
   * The currently set vendor defined certificate builder, or null.
   */
  protected static VendorDefinedCertificateBuilder vendorCertificateBuilder_;

  /**
   * The type of this certificate. One of CertificateType, or one that has a bigger value than
   * VENDOR_DEFINED.
   */
  protected CertificateTypeAttribute certificateType_;

  /**
   * Indicates, if this certificate can be trusted.
   */
  protected BooleanAttribute trusted_;

  /**
   * Categorization of the certificate: 0 = unspecified (default), 1 = token user, 2 = authority, 3
   * = other entity.
   */
  protected LongAttribute certificateCategory_;

  /**
   * Checksum of this certificate.
   */
  protected ByteArrayAttribute checkValue_;

  /**
   * The start date of this certificate's validity.
   */
  protected DateAttribute startDate_;

  /**
   * The end date of this certificate's validity.
   */
  protected DateAttribute endDate_;

  /**
   * The default constructor. An application use this constructor to instanciate a certificate that
   * serves as a template. It may also be useful for working with vendor-defined certificates.
   * 
   */
  public Certificate() {
    super();
    objectClass_.setLongValue(ObjectClass.CERTIFICATE);
  }

  /**
   * Constructor taking the reference to the PKCS#11 module for accessing the object's attributes,
   * the session handle to use for reading the attribute values and the object handle. This
   * constructor read all attributes that a storage object must contain.
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
  protected Certificate(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    objectClass_.setLongValue(ObjectClass.CERTIFICATE);
  }

  /**
   * Get the given certificate type as string.
   * 
   * @param certificateType
   *          The certificate type to get as string.
   * @return A string denoting the object certificate type; e.g. "X.509 Public Key".
   * @preconditions (certificateType <> null)
   * @postconditions (result <> null)
   */
  public static String getCertificateTypeName(Long certificateType) {
    String certificateTypeName;

    if (certificateType == null) {
      throw new NullPointerException("Argument \"certificateType\" must not be null.");
    }

    if (certificateType.equals(CertificateType.X_509_PUBLIC_KEY)) {
      certificateTypeName = "X.509 Public Key";
    } else if (certificateType.equals(CertificateType.X_509_ATTRIBUTE)) {
      certificateTypeName = "X.509 Attribute";
    } else if ((certificateType.longValue() & CertificateType.VENDOR_DEFINED.longValue()) != 0L) {
      certificateTypeName = "Vendor Defined";
    } else {
      certificateTypeName = "<unknown>";
    }

    return certificateTypeName;
  }

  /**
   * The getInstance method of the Object class uses this method to create an instance of a PKCS#11
   * certificate. This method reads the certificate type attribute and calls the getInstance method
   * of the according sub-class. If the certificate type is a vendor defined it uses the
   * VendorDefinedCertificateBuilder set by the application. If no certificate could be constructed,
   * this method returns null.
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

    CertificateTypeAttribute certificateTypeAttribute = new CertificateTypeAttribute();
    getAttributeValue(session, objectHandle, certificateTypeAttribute);

    Long certificateType = certificateTypeAttribute.getLongValue();

    Object newObject;

    if (certificateTypeAttribute.isPresent() && (certificateType != null)) {
      if (certificateType.equals(CertificateType.X_509_PUBLIC_KEY)) {
        newObject = X509PublicKeyCertificate.getInstance(session, objectHandle);
      } else if (certificateType.equals(CertificateType.X_509_ATTRIBUTE)) {
        newObject = X509AttributeCertificate.getInstance(session, objectHandle);
      } else if (certificateType.equals(CertificateType.WTLS)) {
        newObject = WTLSCertificate.getInstance(session, objectHandle);
      } else if ((certificateType.longValue() & CertificateType.VENDOR_DEFINED
          .longValue()) != 0L) {
        newObject = getUnknownCertificate(session, objectHandle);
      } else {
        newObject = getUnknownCertificate(session, objectHandle);
      }
    } else {
      newObject = getUnknownCertificate(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a certificate which has no or an unkown certificate type attribute. This
   * implementation will try to use a vendor defined certificate builder, if such has been set. If
   * this is impossible or fails, it will create just a simple
   * {@link iaik.pkcs.pkcs11.objects.Certificate Certificate }.
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
  protected static Object getUnknownCertificate(Session session, long objectHandle)
      throws TokenException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    Object newObject;
    if (vendorCertificateBuilder_ != null) {
      try {
        newObject = vendorCertificateBuilder_.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of certificate
        newObject = new Certificate(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of certificate
      newObject = new Certificate(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Set a vendor-defined certificate builder that should be called to create an instance of an
   * vendor-defined PKCS#11 certificate; i.e. an instance of a vendor defined sub-class of this
   * class.
   * 
   * @param builder
   *          The vendor-defined certificate builder. Null to clear any previously installed
   *          vendor-defined builder.
   */
  public static void setVendorDefinedCertificateBuilder(
      VendorDefinedCertificateBuilder builder) {
    vendorCertificateBuilder_ = builder;
  }

  /**
   * Get the currently set vendor-defined certificate builder.
   * 
   * @return The currently set vendor-defined certificate builder or null if none is set.
   */
  public static VendorDefinedCertificateBuilder getVendorDefinedCertificateBuilder() {
    return vendorCertificateBuilder_;
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
  protected static void putAttributesInTable(Certificate object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.CERTIFICATE_TYPE, object.certificateType_);
    object.attributeTable_.put(Attribute.TRUSTED, object.trusted_);
    object.attributeTable_.put(Attribute.CERTIFICATE_CATEGORY,
        object.certificateCategory_);
    object.attributeTable_.put(Attribute.CHECK_VALUE, object.checkValue_);
    object.attributeTable_.put(Attribute.START_DATE, object.startDate_);
    object.attributeTable_.put(Attribute.END_DATE, object.endDate_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    certificateType_ = new CertificateTypeAttribute();
    trusted_ = new BooleanAttribute(Attribute.TRUSTED);
    certificateCategory_ = new LongAttribute(Attribute.CERTIFICATE_CATEGORY);
    checkValue_ = new ByteArrayAttribute(Attribute.CHECK_VALUE);
    startDate_ = new DateAttribute(Attribute.START_DATE);
    endDate_ = new DateAttribute(Attribute.END_DATE);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof Certificate) and (result.equals(this))
   */
  public java.lang.Object clone() {
    Certificate clone = (Certificate) super.clone();

    clone.certificateType_ = (CertificateTypeAttribute) this.certificateType_.clone();
    clone.trusted_ = (BooleanAttribute) this.trusted_.clone();
    clone.certificateCategory_ = (LongAttribute) this.certificateCategory_.clone();
    clone.checkValue_ = (ByteArrayAttribute) this.checkValue_.clone();
    clone.startDate_ = (DateAttribute) this.startDate_.clone();
    clone.endDate_ = (DateAttribute) this.endDate_.clone();

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

    if (otherObject instanceof Certificate) {
      Certificate other = (Certificate) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.certificateType_.equals(other.certificateType_)
              && this.trusted_.equals(other.trusted_)
              && this.certificateCategory_.equals(other.certificateCategory_)
              && this.checkValue_.equals(other.checkValue_)
              && this.startDate_.equals(other.startDate_) && this.endDate_
                .equals(other.endDate_));
    }

    return equal;
  }

  /**
   * Gets the certificate type attribute of the PKCS#11 certificate. Its value must be one of those
   * defined in the CertificateType interface or one with an value bigger than
   * CertificateType.VENDOR_DEFINED.
   * 
   * @return The certificate type attribute.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getCertificateType() {
    return certificateType_;
  }

  /**
   * Gets the trusted attribute of the PKCS#11 certificate.
   * 
   * @return The trusted attribute.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute getTrusted() {
    return trusted_;
  }

  /**
   * Gets the certificate category attribute of the PKCS#11 certificate.
   * 
   * @return The certificate category attribute.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getCertificateCategory() {
    return certificateCategory_;
  }

  /**
   * Gets the check value attribute of of the PKCS#11 certificate.
   * 
   * @return The check value attribute.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getCheckValue() {
    return checkValue_;
  }

  /**
   * Gets the start date attribute of the validity of the PKCS#11 certificate.
   * 
   * @return The start date of validity.
   * 
   * @postconditions (result <> null)
   */
  public DateAttribute getStartDate() {
    return startDate_;
  }

  /**
   * Gets the end date attribute of the validity of the PKCS#11 certificate.
   * 
   * @return The end date of validity.
   * 
   * @postconditions (result <> null)
   */
  public DateAttribute getEndDate() {
    return endDate_;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return certificateType_.hashCode();
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

    // Object.getAttributeValue(session, objectHandle_, trusted_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { trusted_,
        certificateCategory_, checkValue_, startDate_, endDate_ });
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
    StringBuffer buffer = new StringBuffer(128);

    buffer.append(super.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Certificate Type: ");
    if (certificateType_ != null) {
      buffer.append(certificateType_.toString());
    } else {
      buffer.append("<unavailable>");
    }

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Trusted: ");
    buffer.append(trusted_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Certificate Category: ");
    buffer.append(certificateCategory_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Check Value: ");
    buffer.append(checkValue_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Start Date: ");
    buffer.append(startDate_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("End Date: ");
    buffer.append(endDate_.toString());

    return buffer.toString();
  }

}
