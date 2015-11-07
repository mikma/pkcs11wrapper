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
 * This is the base class for hardware feature classes. Objects of this class represent hardware
 * features as specified by PKCS#11 v2.20. A hardware feature is of a specific type:
 * MONOTONIC_COUNTER, CLOCK, CKH_USER_INTERFAC or VENDOR_DEFINED. If an application needs to use
 * vendor-defined hardware features, it must set a VendorDefinedHardwareFeatureBuilder using the
 * setVendorDefinedHardwareFeatureBuilder method.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (hardwareFeatureType_ <> null)
 */
public class HardwareFeature extends Object {

  /**
   * This interface defines the available hardware feature types as defined by PKCS#11 2.20:
   * MONOTONIC_COUNTER, CLOCK, CKH_USER_INTERFAC or VENDOR_DEFINED.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface FeatureType {

    /**
     * The indentifier for a monotonic counter.
     */
    static public final Long MONOTONIC_COUNTER = new Long(
        PKCS11Constants.CKH_MONOTONIC_COUNTER);

    /**
     * The indentifier for a clock.
     */
    static public final Long CLOCK = new Long(PKCS11Constants.CKH_CLOCK);

    /**
     * The indentifier for a user interface.
     */
    static public final Long USER_INTERFACE = new Long(PKCS11Constants.CKH_USER_INTERFACE);

    /**
     * The indentifier for a VENDOR_DEFINED hardware feature. Any Long object with a value bigger
     * than this one is also a valid vendor-defined hardware feature type identifier.
     */
    static public final Long VENDOR_DEFINED = new Long(PKCS11Constants.CKH_VENDOR_DEFINED);

  }

  /**
   * If an application uses vendor defined hardware features, it must implement this interface and
   * install such an object handler using setVendorDefinedHardwareFeatureBuilder.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface VendorDefinedHardwareFeatureBuilder {

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
   * The currently set vendor defined hardware feature builder, or null.
   */
  protected static VendorDefinedHardwareFeatureBuilder vendorHardwareFeatureBuilder_;

  /**
   * The type of this hardware feature. Its value is one of FeatureType, or one that has a bigger
   * value than VENDOR_DEFINED.
   */
  protected HardwareFeatureTypeAttribute hardwareFeatureType_;

  /**
   * The default constructor. An application use this constructor to instanciate a hardware feature
   * that serves as a template. It may also be useful for working with vendor-defined hardware
   * features.
   * 
   */
  public HardwareFeature() {
    super();
    objectClass_.setLongValue(ObjectClass.HW_FEATURE);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 hardware feature.
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
  protected HardwareFeature(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    objectClass_.setLongValue(ObjectClass.HW_FEATURE);
  }

  /**
   * Get the given hardware feature type as string.
   * 
   * @param hardwareFeatureType
   *          The hardware feature type to get as string.
   * @return A string denoting the object hardware feature type; e.g. "Clock".
   * @preconditions (hardwareFeatureType <> null)
   * @postconditions (result <> null)
   */
  public static String getHardwareFeatureTypeName(Long hardwareFeatureType) {
    String hardwareFeatureTypeName;

    if (hardwareFeatureType == null) {
      throw new NullPointerException("Argument \"hardwareFeatureType\" must not be null.");
    }

    if (hardwareFeatureType.equals(FeatureType.MONOTONIC_COUNTER)) {
      hardwareFeatureTypeName = "Monotonic Counter";
    } else if (hardwareFeatureType.equals(FeatureType.CLOCK)) {
      hardwareFeatureTypeName = "Clock";
    } else if (hardwareFeatureType.equals(FeatureType.USER_INTERFACE)) {
      hardwareFeatureTypeName = "User Interface";
    } else if ((hardwareFeatureType.longValue() & FeatureType.VENDOR_DEFINED.longValue()) != 0L) {
      hardwareFeatureTypeName = "Vendor Defined";
    } else {
      hardwareFeatureTypeName = "<unknown>";
    }

    return hardwareFeatureTypeName;
  }

  /**
   * Called by sub-classes to create an instance of a PKCS#11 hardware feature. This method reads
   * the hardware feature type attribute and calls the getInstance method of the according
   * sub-class. If the hardware feature type is a vendor defined it uses the
   * VendorDefinedHardwareFeatureBuilder set by the application. If no hardware feature could be
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

    HardwareFeatureTypeAttribute hardwareFeatureTypeAttribute = new HardwareFeatureTypeAttribute();
    getAttributeValue(session, objectHandle, hardwareFeatureTypeAttribute);

    Long hardwareFeatureType = hardwareFeatureTypeAttribute.getLongValue();

    Object newObject;

    if (hardwareFeatureTypeAttribute.isPresent() && (hardwareFeatureType != null)) {
      if (hardwareFeatureType.equals(FeatureType.MONOTONIC_COUNTER)) {
        newObject = MonotonicCounter.getInstance(session, objectHandle);
      } else if (hardwareFeatureType.equals(FeatureType.CLOCK)) {
        newObject = Clock.getInstance(session, objectHandle);
      } else if (hardwareFeatureType.equals(FeatureType.USER_INTERFACE)) {
        // TODO: add user interface object
        // newObject = UserInterface.getInstance(session, objectHandle);
        newObject = getUnknownHardwareFeature(session, objectHandle);
      } else if ((hardwareFeatureType.longValue() & FeatureType.VENDOR_DEFINED
          .longValue()) != 0L) {
        newObject = getUnknownHardwareFeature(session, objectHandle);
      } else {
        newObject = getUnknownHardwareFeature(session, objectHandle);
      }
    } else {
      newObject = getUnknownHardwareFeature(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Try to create a hardware feature which has no or an unkown harware feature type attribute. This
   * implementation will try to use a vendor defined hardware feature builder, if such has been set.
   * If this is impossible or fails, it will create just a simple
   * {@link iaik.pkcs.pkcs11.objects.HardwareFeature HardwareFeature}.
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
  protected static Object getUnknownHardwareFeature(Session session, long objectHandle)
      throws TokenException {
    if (session == null) {
      throw new NullPointerException("Argument \"session\" must not be null.");
    }

    Object newObject;
    if (vendorHardwareFeatureBuilder_ != null) {
      try {
        newObject = vendorHardwareFeatureBuilder_.build(session, objectHandle);
      } catch (PKCS11Exception ex) {
        // we can just treat it like some unknown type of hardware feature
        newObject = new HardwareFeature(session, objectHandle);
      }
    } else {
      // we can just treat it like some unknown type of hardware feature
      newObject = new HardwareFeature(session, objectHandle);
    }

    return newObject;
  }

  /**
   * Set a vendor-defined hardware feature builder that should be called to create an* instance of
   * an vendor-defined PKCS#11 hardware feature; i.e. an instance of a vendor defined sub-class of
   * this class.
   * 
   * @param builder
   *          The vendor-defined hardware feature builder. Null to clear any previously installed
   *          vendor-defined builder.
   */
  public static void setVendorDefinedHardwareFeatureBuilder(
      VendorDefinedHardwareFeatureBuilder builder) {
    vendorHardwareFeatureBuilder_ = builder;
  }

  /**
   * Get the currently set vendor-defined hardware feature builder.
   * 
   * @return The currently set vendor-defined hardware feature builder or null if none is set.
   */
  public static VendorDefinedHardwareFeatureBuilder getVendorDefinedHardwareFeatureBuilder() {
    return vendorHardwareFeatureBuilder_;
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
  protected static void putAttributesInTable(HardwareFeature object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.HW_FEATURE_TYPE, object.hardwareFeatureType_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   * 
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    hardwareFeatureType_ = new HardwareFeatureTypeAttribute();

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof HardwareFeature) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    HardwareFeature clone = (HardwareFeature) super.clone();

    clone.hardwareFeatureType_ = (HardwareFeatureTypeAttribute) this.hardwareFeatureType_
        .clone();

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

    if (otherObject instanceof HardwareFeature) {
      HardwareFeature other = (HardwareFeature) otherObject;
      equal = (this == other)
          || (super.equals(other) && this.hardwareFeatureType_
              .equals(other.hardwareFeatureType_));
    }

    return equal;
  }

  /**
   * Gets the hardware feature type attribute of the PKCS#11 key. Its value must be one of those
   * defined in the FeatureType interface or one with an value bigger than
   * FeatureType.VENDOR_DEFINED.
   * 
   * @return The hardware feature type identifier.
   * 
   * @postconditions (result <> null)
   */
  public LongAttribute getHardwareFeatureType() {
    return hardwareFeatureType_;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return hardwareFeatureType_.hashCode();
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
    buffer.append("Hardware Feature Type: ");
    if (hardwareFeatureType_ != null) {
      buffer.append(hardwareFeatureType_.toString());
    } else {
      buffer.append("<unavailable>");
    }

    return buffer.toString();
  }

}
