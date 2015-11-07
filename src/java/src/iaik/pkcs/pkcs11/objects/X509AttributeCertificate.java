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
 * Objects of this class represent X.509 attribute certificate as specified by PKCS#11 v2.11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (owner_ <> null) and (acIssuer_ <> null) and (serialNumber_ <> null) and (attrTypes_
 *             <> null) and (value_ <> null)
 */
public class X509AttributeCertificate extends Certificate {

  /**
   * The owner attribute of this certificate.
   */
  protected ByteArrayAttribute owner_;

  /**
   * The owner attribute of this certificate.
   */
  protected ByteArrayAttribute acIssuer_;

  /**
   * The serial number attribute of this certificate.
   */
  protected ByteArrayAttribute serialNumber_;

  /**
   * The attribute types attribute of this certificate.
   */
  protected ByteArrayAttribute attrTypes_;

  /**
   * The value attribute of this certificate; i.e. BER-encoded certificate.
   */
  protected ByteArrayAttribute value_;

  /**
   * Deafult Constructor.
   * 
   */
  public X509AttributeCertificate() {
    super();
    certificateType_.setLongValue(CertificateType.X_509_ATTRIBUTE);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 X.509 attribute certificate.
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
  protected X509AttributeCertificate(Session session, long objectHandle)
      throws TokenException {
    super(session, objectHandle);
    certificateType_.setLongValue(CertificateType.X_509_ATTRIBUTE);
  }

  /**
   * The getInstance method of the Certificate class uses this method to create an instance of a
   * PKCS#11 X.509 attribute certificate.
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
    return new X509AttributeCertificate(session, objectHandle);
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
  protected static void putAttributesInTable(X509AttributeCertificate object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.OWNER, object.owner_);
    object.attributeTable_.put(Attribute.AC_ISSUER, object.acIssuer_);
    object.attributeTable_.put(Attribute.SERIAL_NUMBER, object.serialNumber_);
    object.attributeTable_.put(Attribute.ATTR_TYPES, object.attrTypes_);
    object.attributeTable_.put(Attribute.VALUE, object.value_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    owner_ = new ByteArrayAttribute(Attribute.OWNER);
    acIssuer_ = new ByteArrayAttribute(Attribute.AC_ISSUER);
    serialNumber_ = new ByteArrayAttribute(Attribute.SERIAL_NUMBER);
    attrTypes_ = new ByteArrayAttribute(Attribute.ATTR_TYPES);
    value_ = new ByteArrayAttribute(Attribute.VALUE);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof X509AttributeCertificate) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    X509AttributeCertificate clone = (X509AttributeCertificate) super.clone();

    clone.owner_ = (ByteArrayAttribute) this.owner_.clone();
    clone.acIssuer_ = (ByteArrayAttribute) this.acIssuer_.clone();
    clone.serialNumber_ = (ByteArrayAttribute) this.serialNumber_.clone();
    clone.attrTypes_ = (ByteArrayAttribute) this.attrTypes_.clone();
    clone.value_ = (ByteArrayAttribute) this.value_.clone();

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

    if (otherObject instanceof X509AttributeCertificate) {
      X509AttributeCertificate other = (X509AttributeCertificate) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.owner_.equals(other.owner_)
              && this.acIssuer_.equals(other.acIssuer_)
              && this.serialNumber_.equals(other.serialNumber_)
              && this.attrTypes_.equals(other.attrTypes_) && this.value_
                .equals(other.value_));
    }

    return equal;
  }

  /**
   * Gets the owner attribute of this X.509 attribute certificate.
   * 
   * @return The owner attribute of this X.509 attribute certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getOwner() {
    return owner_;
  }

  /**
   * Gets the attribute certificate issuer attribute of this X.509 attribute certificate.
   * 
   * @return The attribute certificate issuer attribute of this X.509 attribute certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getAcIssuer() {
    return acIssuer_;
  }

  /**
   * Gets the serial number attribute of this X.509 attribute certificate.
   * 
   * @return The serial number attribute of this X.509 attribute certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getSerialNumber() {
    return serialNumber_;
  }

  /**
   * Gets the attribute types attribute of this X.509 attribute certificate.
   * 
   * @return The attribute types attribute of this X.509 attribute certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getAttrTypes() {
    return attrTypes_;
  }

  /**
   * Gets the value attribute of this X.509 attribute certificate.
   * 
   * @return The value attribute of this X.509 attribute certificate.
   * 
   * @postconditions (result <> null)
   */
  public ByteArrayAttribute getValue() {
    return value_;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return acIssuer_.hashCode() ^ serialNumber_.hashCode();
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

    // Object.getAttributeValue(session, objectHandle_, owner_);
    // Object.getAttributeValue(session, objectHandle_, acIssuer_);
    // Object.getAttributeValue(session, objectHandle_, serialNumber_);
    // Object.getAttributeValue(session, objectHandle_, attrTypes_);
    // Object.getAttributeValue(session, objectHandle_, value_);
    Object.getAttributeValues(session, objectHandle_, new Attribute[] { owner_,
        acIssuer_, serialNumber_, attrTypes_, value_ });
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
    buffer.append("Owner (DER, hex): ");
    buffer.append(owner_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Attribute Certificate Issuer (DER, hex): ");
    buffer.append(acIssuer_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Serial Number (DER, hex): ");
    buffer.append(serialNumber_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Attribute Types (BER, hex): ");
    buffer.append(attrTypes_.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Value (BER, hex): ");
    buffer.append(value_.toString());

    return buffer.toString();
  }

}
