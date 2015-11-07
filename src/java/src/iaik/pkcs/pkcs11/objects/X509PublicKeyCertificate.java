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
 * Objects of this class represent X.509 public key certificate as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (subject_ <> null) and (id_ <> null) and (issuer_ <> null) and (serialNumber_ <>
 *             null) and (value_ <> null)
 */
public class X509PublicKeyCertificate extends Certificate {

  /**
   * The subject attribute of this certificate.
   */
  protected ByteArrayAttribute subject_;

  /**
   * The ID attribute of this certificate.
   */
  protected ByteArrayAttribute id_;

  /**
   * The issuer attribute of this certificate.
   */
  protected ByteArrayAttribute issuer_;

  /**
   * The serial number attribute of this certificate. Notice that netscape needs the raw serial
   * number, but PKCS#11 defines this attribute as DER encoded integer.
   */
  protected ByteArrayAttribute serialNumber_;

  /**
   * The value attribute of this certificate; i.e. BER-encoded certificate.
   */
  protected ByteArrayAttribute value_;

  /**
   * This attribute gives the URL where the complete certificate can be obtained.
   */
  protected CharArrayAttribute url_;

  /**
   * SHA-1 hash of the subject public key.
   */
  protected ByteArrayAttribute hashOfSubjectPublicKey_;

  /**
   * SHA-1 hash of the issuer public key.
   */
  protected ByteArrayAttribute hashOfIssuerPublicKey_;

  /**
   * Java MIDP security domain: 0 = unspecified (default value), 1 = manufacturer, 2 = operator, 3 =
   * third party
   */
  protected LongAttribute javaMidpSecurityDomain_;

  /**
   * Deafult Constructor.
   * 
   */
  public X509PublicKeyCertificate() {
    super();
    certificateType_.setLongValue(CertificateType.X_509_PUBLIC_KEY);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 X.509 public key certificate.
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
  protected X509PublicKeyCertificate(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    certificateType_.setLongValue(CertificateType.X_509_PUBLIC_KEY);
  }

  /**
   * The getInstance method of the Certificate class uses this method to create an instance of a
   * PKCS#11 X.509 public key certificate.
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
    return new X509PublicKeyCertificate(session, objectHandle);
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
  protected static void putAttributesInTable(X509PublicKeyCertificate object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.SUBJECT, object.subject_);
    object.attributeTable_.put(Attribute.ID, object.id_);
    object.attributeTable_.put(Attribute.ISSUER, object.issuer_);
    object.attributeTable_.put(Attribute.SERIAL_NUMBER, object.serialNumber_);
    object.attributeTable_.put(Attribute.VALUE, object.value_);
    object.attributeTable_.put(Attribute.URL, object.url_);
    object.attributeTable_.put(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY,
        object.hashOfSubjectPublicKey_);
    object.attributeTable_.put(Attribute.HASH_OF_ISSUER_PUBLIC_KEY,
        object.hashOfIssuerPublicKey_);
    object.attributeTable_.put(Attribute.JAVA_MIDP_SECURITY_DOMAIN,
        object.javaMidpSecurityDomain_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    subject_ = new ByteArrayAttribute(Attribute.SUBJECT);
    id_ = new ByteArrayAttribute(Attribute.ID);
    issuer_ = new ByteArrayAttribute(Attribute.ISSUER);
    serialNumber_ = new ByteArrayAttribute(Attribute.SERIAL_NUMBER);
    value_ = new ByteArrayAttribute(Attribute.VALUE);
    url_ = new CharArrayAttribute(Attribute.URL);
    hashOfSubjectPublicKey_ = new ByteArrayAttribute(Attribute.HASH_OF_SUBJECT_PUBLIC_KEY);
    hashOfIssuerPublicKey_ = new ByteArrayAttribute(Attribute.HASH_OF_ISSUER_PUBLIC_KEY);
    javaMidpSecurityDomain_ = new LongAttribute(Attribute.JAVA_MIDP_SECURITY_DOMAIN);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof X509PublicKeyCertificate) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    X509PublicKeyCertificate clone = (X509PublicKeyCertificate) super.clone();

    clone.subject_ = (ByteArrayAttribute) this.subject_.clone();
    clone.id_ = (ByteArrayAttribute) this.id_.clone();
    clone.issuer_ = (ByteArrayAttribute) this.issuer_.clone();
    clone.serialNumber_ = (ByteArrayAttribute) this.serialNumber_.clone();
    clone.value_ = (ByteArrayAttribute) this.value_.clone();
    clone.url_ = (CharArrayAttribute) this.url_.clone();
    clone.hashOfSubjectPublicKey_ = (ByteArrayAttribute) this.hashOfSubjectPublicKey_
        .clone();
    clone.hashOfIssuerPublicKey_ = (ByteArrayAttribute) this.hashOfIssuerPublicKey_
        .clone();
    clone.javaMidpSecurityDomain_ = (LongAttribute) this.javaMidpSecurityDomain_.clone();

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

    if (otherObject instanceof X509PublicKeyCertificate) {
      X509PublicKeyCertificate other = (X509PublicKeyCertificate) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.subject_.equals(other.subject_)
              && this.id_.equals(other.id_) && this.issuer_.equals(other.issuer_)
              && this.serialNumber_.equals(other.serialNumber_)
              && this.value_.equals(other.value_) && this.url_.equals(other.url_)
              && this.hashOfSubjectPublicKey_.equals(other.hashOfSubjectPublicKey_)
              && this.hashOfIssuerPublicKey_.equals(other.hashOfIssuerPublicKey_) && this.javaMidpSecurityDomain_
                .equals(other.javaMidpSecurityDomain_));
    }

    return equal;
  }

  /**
   * Gets the subject attribute of this X.509 public key certificate.
   * 
   * @return The subject attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getSubject() {
    return subject_;
  }

  /**
   * Gets the ID attribute of this X.509 public key certificate.
   * 
   * @return The ID attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getId() {
    return id_;
  }

  /**
   * Gets the issuer attribute of this X.509 public key certificate.
   * 
   * @return The issuer attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getIssuer() {
    return issuer_;
  }

  /**
   * Gets the serial number attribute of this X.509 public key certificate.
   * 
   * @return The serial number attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getSerialNumber() {
    return serialNumber_;
  }

  /**
   * Gets the value attribute of this X.509 public key certificate.
   * 
   * @return The value attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getValue() {
    return value_;
  }

  /**
   * Get the URL attribute of this object.
   * 
   * @return Contains the URL as a char array.
   * 
   * @postconditions (result <> null)
   */
  public CharArrayAttribute getUrl() {
    return url_;
  }

  /**
   * Gets the hash of subject public key attribute of this X.509 public key certificate.
   * 
   * @return The hash of subject public key attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getHashOfSubjectPublicKey() {
    return hashOfSubjectPublicKey_;
  }

  /**
   * Gets the hash of issuer public key attribute of this X.509 public key certificate.
   * 
   * @return The hash of issuer public key attribute of this X.509 public key certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getHashOfIssuerPublicKey() {
    return hashOfIssuerPublicKey_;
  }

  /**
   * Gets the java midp security domain attribute of the PKCS#11 certificate.
   * 
   * @return The java midp security domain category attribute.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getJavaMidpSecurityDomain() {
    return javaMidpSecurityDomain_;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return issuer_.hashCode() ^ serialNumber_.hashCode();
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
    // Object.getAttributeValue(session, objectHandle_, id_);
    // Object.getAttributeValue(session, objectHandle_, issuer_);
    // Object.getAttributeValue(session, objectHandle_, serialNumber_);
    // Object.getAttributeValue(session, objectHandle_, value_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { subject_, id_,
        issuer_, serialNumber_, value_ });
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { url_,
        hashOfSubjectPublicKey_, hashOfIssuerPublicKey_, javaMidpSecurityDomain_ });
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
    buffer.append("ID (hex): ");
    buffer.append(id_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Issuer (DER, hex): ");
    buffer.append(issuer_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Serial Number (DER, hex): ");
    buffer.append(serialNumber_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Value (BER, hex): ");
    buffer.append(value_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("URL: ");
    buffer.append(url_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Hash Of Subject Public Key: ");
    buffer.append(hashOfSubjectPublicKey_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Hash Of Issuer Public Key: ");
    buffer.append(hashOfIssuerPublicKey_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Java MIDP Security Domain: ");
    buffer.append(javaMidpSecurityDomain_.toString());

    return buffer.toString();
  }

}
