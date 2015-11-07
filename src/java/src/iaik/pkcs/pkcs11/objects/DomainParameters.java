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
 * An object of this class represents domain parameters as defined by PKCS#11 2.11. Domain
 * parameters are of a specific type: DSA, DH or X9_42_DH. If an application needs to use
 * vendor-defined domain parameters, it must set a VendorDefinedDomainParametersBuilder using the
 * setVendorDefinedDomainParametersBuilder method.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (keyType_ <> null) and (local_ <> null)
 */
public class DomainParameters extends Storage {

  /**
   * If an application uses vendor defined DomainParameters, it must implement this interface and
   * install such an object handler using setVendorDefinedDomainParametersBuilder.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface VendorDefinedDomainParametersBuilder {

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
   * The currently set vendor defined DomainParameters builder, or null.
   */
  protected static VendorDefinedDomainParametersBuilder vendorDomainParametersBuilder_;

  /**
   * The type of this key. Its value is one of KeyType, or one that has a bigger value than
   * VENDOR_DEFINED.
   */
  protected KeyTypeAttribute keyType_;

  /**
   * True, if this key was created (generated or copiedfrom a different key) on the token.
   */
  protected BooleanAttribute local_;

  /**
   * The default constructor. An application uses this constructor to instanciate a key that serves
   * as a template. It may also be useful for working with vendor-defined domain parameters.
   * 
   */
  public DomainParameters() {
    super();
    objectClass_.setLongValue(ObjectClass.DOMAIN_PARAMETERS);
  }

  /**
   * Called by sub-classes to create an instance of PKCS#11 domain parameters.
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
  protected DomainParameters(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    objectClass_.setLongValue(ObjectClass.DOMAIN_PARAMETERS);
  }

  /**
   * Set a vendor-defined DomainParameters builder that should be called to create an instance of
   * vendor-defined PKCS#11 domain parameters; i.e. an instance of a vendor defined sub-class of
   * this class.
   * 
   * @param builder
   *          The vendor-defined DomainParameters builder. Null to clear any previously installed
   *          vendor-defined builder.
   */
  public static void setVendorDefinedDomainParametersBuilder(
      VendorDefinedDomainParametersBuilder builder) {
    vendorDomainParametersBuilder_ = builder;
  }

  /**
   * Get the currently set vendor-defined DomainParameters builder.
   * 
   * @return The currently set vendor-defined DomainParameters builder or null if none is set.
   */
  public static VendorDefinedDomainParametersBuilder getVendorDefinedDomainParametersBuilder() {
    return vendorDomainParametersBuilder_;
  }

  /**
   * The getInstance method of the Object class uses this method to create an instance of PKCS#11
   * domain parameters. This method reads the key type attribute and calls the getInstance method of
   * the according sub-class. If the key type is a vendor defined or an unknown it uses the
   * VendorDefinedDomainParametersBuilder set by the application. If no domain parameters could be
   * constructed, this method returns null.
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
      if (keyType.equals(Key.KeyType.DSA)) {
        newObject = DSAParams.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.DH)) {
        newObject = DHParams.getInstance(session, objectHandle);
      } else if (keyType.equals(Key.KeyType.X9_42_DH)) {
        newObject = X942DHParams.getInstance(session, objectHandle);
      } else if ((keyType.longValue() & Key.KeyType.VENDOR_DEFINED.longValue()) != 0L) {
        newObject = getUnknownDomainParameters(session, objectHandle);
      } else {
        newObject = getUnknownDomainParameters(session, objectHandle);
      }
    } else {
      newObject = getUnknownDomainParameters(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a domain parameters which has no or an unkown key type type attribute. This
   * implementation will try to use a vendor defined domain parameters builder, if such has been
   * set. If this is impossible or fails, it will create just a simple
   * {@link iaik.pkcs.pkcs11.objects.DomainParameters DomainParameters}.
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
  protected static Object getUnknownDomainParameters(Session session, long objectHandle)
      throws TokenException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    Object newObject;
    if (vendorDomainParametersBuilder_ != null) {
      try {
        newObject = vendorDomainParametersBuilder_.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of domain parameters
        newObject = new DomainParameters(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of domain parameters
      newObject = new DomainParameters(session, objectHandle);
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
  protected static void putAttributesInTable(DomainParameters object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.KEY_TYPE, object.keyType_);
    object.attributeTable_.put(Attribute.LOCAL, object.local_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    keyType_ = new KeyTypeAttribute();
    local_ = new BooleanAttribute(Attribute.LOCAL);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof DomainParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    DomainParameters clone = (DomainParameters) super.clone();

    clone.keyType_ = (KeyTypeAttribute) this.keyType_.clone();
    clone.local_ = (BooleanAttribute) this.local_.clone();

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

    if (otherObject instanceof DomainParameters) {
      DomainParameters other = (DomainParameters) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.keyType_.equals(other.keyType_) && this.local_
              .equals(other.local_));
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
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return keyType_.hashCode() ^ local_.hashCode();
  }

  /**
   * Check, if this key is a local key; i.e. was generated on the token or created via copy from a
   * different key on the token.
   * 
   * @return Its value is true, if the key was created on the token.
   * 
   * @postconditions (result <> null)
   */
  public BooleanAttribute isLocal() {
    return local_;
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

    Object.getAttributeValue(session, objectHandle_, local_);
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
    buffer.append("Local: ");
    buffer.append(local_.toString());

    return buffer.toString();
  }

}
