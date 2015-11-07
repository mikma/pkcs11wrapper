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

//import java.util.Collection;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.Constants;

import java.util.Enumeration;

/**
 * An object of this class is a generic template. Its purpose is to serve as a container for a set
 * of attributes that the application can use to search for objects. This can be especially useful,
 * if an application wants to search for objects in a very restricted manner. For instance, if an
 * application wants to find all objects which contain an ID attribute with an given value, it can
 * use this class. If it would use the Key class, it would only find Key objects. Moreover, objects
 * of this class may serve as templates for object creation and key and key-pair generation.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (attributes_ <> null)
 */
public class GenericTemplate extends Object {

  /**
   * The default constructor. Creates an object with no attributes.
   * 
   */
  public GenericTemplate() {
    super();
    attributeTable_.clear(); // we do not want any attributes in this object by default
  }

  /**
   * Adds an attribute to this generic search template.
   * 
   * @param attribute
   *          The attribute to add to the template.
   * @preconditions (attribute <> null)
   * 
   */
  public void addAttribute(Attribute attribute) {
    if (attribute == null) {
      throw new NullPointerException("Argument \"attribute\" must not be null.");
    }
    // attributes_.addElement(attribute);
    attributeTable_.put(attribute.getType(), attribute);
  }

  /**
   * Adds all attributes of the given object to this generic template. Notice that this method does
   * not automatically clone the attributes. If the application needs this, it must clone the
   * argument object before.
   * 
   * @param object
   *          The object that holds the attributes to add to the template.
   * @preconditions (object <> null)
   * 
   */
  public void addAllAttributes(Object object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }
    Enumeration newAttributeKeysEnumeration = object.attributeTable_.keys();
    while (newAttributeKeysEnumeration.hasMoreElements()) {
      java.lang.Object newKey = newAttributeKeysEnumeration.nextElement();
      attributeTable_.put(newKey, object.attributeTable_.get(newKey));
    }
    // attributeTable_.putAll(); does not exist in JDK 1.1
  }

  /**
   * Adds all attributes of the given object which have their present flag set to this generic
   * template. Notice that this method does not automatically clone the attributes. If the
   * application needs this, it must clone the argument object before.
   * 
   * @param object
   *          The object that holds the attributes to add to the template.
   * @preconditions (object <> null)
   * 
   */
  public void addAllPresentAttributes(Object object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }
    Enumeration attributeEnumaeration = object.attributeTable_.elements();
    while (attributeEnumaeration.hasMoreElements()) {
      Attribute attribute = (Attribute) attributeEnumaeration.nextElement();
      if (attribute.isPresent()) {
        attributeTable_.put(attribute.getType(), attribute);
      }
    }
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof GenericTemplate) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    GenericTemplate clone = (GenericTemplate) super.clone();

    clone.attributeTable_.clear(); // we do not want any attributes in this object by default

    // make a deep clone of all attributes
    Enumeration attributesEnumeration = attributeTable_.elements();
    while (attributesEnumeration.hasMoreElements()) {
      Attribute attribute = (Attribute) attributesEnumeration.nextElement();
      Attribute clonedAttribute = (Attribute) attribute.clone();
      clone.attributeTable_.put(clonedAttribute.getType(), clonedAttribute); // put all cloned
                                                                             // attributes into the
                                                                             // new table
    }

    return clone;
  }

  /**
   * Checks, if the given attributte is in this template. More precisely, it returns true, if there
   * is any attribute in this template for which attribute.equals(otherAttribute) returns true.
   * 
   * @param attribute
   *          The attribute to look for.
   * @return True, if the attribute is in the template. False, otherwise.
   * @preconditions (attribute <> null)
   * 
   */
  public boolean containsAttribute(Attribute attribute) {
    if (attribute == null) {
      throw new NullPointerException("Argument \"attribute\" must not be null.");
    }
    return attributeTable_.containsKey(attribute.getType());
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

    if (otherObject instanceof GenericTemplate) {
      GenericTemplate other = (GenericTemplate) otherObject;
      equal = (this == other) || (this.attributeTable_.equals(other.attributeTable_));
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
    return attributeTable_.hashCode();
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
    if (objectHandle_ == -1) {
      throw new TokenException(
          "Object handle is not set to an valid value. Use setObjectHandle(long) to set.");
    }

    super.readAttributes(session);

    Enumeration attributeEnumeration = attributeTable_.elements();
    while (attributeEnumeration.hasMoreElements()) {
      Attribute attribute = (Attribute) attributeEnumeration.nextElement();
      Object.getAttributeValue(session, objectHandle_, attribute);
    }
  }

  /**
   * Removes the given attribute from the template. More precisely, it removes the attribute from
   * the template which has the same type as the given attribute. Notice that type in this context
   * does not refer the the type of data in the attribute's value. For instance, Attribute.SIGN is a
   * type of an attribute.
   * 
   * @param attribute
   *          The attribute to remove.
   * @return The removed attribute, if the attribute was in the template. Null, otherwise.
   * @preconditions (attribute <> null)
   * 
   */
  public Attribute removeAttribute(Attribute attribute) {
    if (attribute == null) {
      throw new NullPointerException("Argument \"attribute\" must not be null.");
    }

    return (Attribute) attributeTable_.remove(attribute.getType());
  }

  /**
   * Removes all attributes of the given object from this generic template. More precisely, it
   * removes the attributes from the template which have the same type as an attribute of the given
   * object. Notice that type in this context does not refer the the type of data in the attribute's
   * value. For instance, Attribute.SIGN is a type of an attribute.
   * 
   * @param object
   *          The object that holds the attributes to add to the template.
   * @preconditions (object <> null)
   * 
   */
  public void removeAllAttributes(Object object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }
    Enumeration keysToRemove = object.attributeTable_.keys();
    while (keysToRemove.hasMoreElements()) {
      attributeTable_.remove(keysToRemove.nextElement());
    }
  }

  /**
   * Removes all attributes of the given object which have their present flag set from this generic
   * template. More precisely, it removes the attributes from the template which have the same type
   * as an attribute of the given object. Notice that type in this context does not refer the the
   * type of data in the attribute's value. For instance, Attribute.SIGN is a type of an attribute.
   * 
   * @param object
   *          The object that holds the attributes to add to the template.
   * @preconditions (object <> null)
   * 
   */
  public void removeAllPresentAttributes(Object object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }
    Enumeration keysToRemove = object.attributeTable_.keys();
    while (keysToRemove.hasMoreElements()) {
      Attribute attribute = (Attribute) object.attributeTable_.get(keysToRemove
          .nextElement());
      if (attribute.isPresent()) {
        attributeTable_.remove(attribute);
      }
    }
  }

  /**
   * Set the present flags of all attributes of this object to the given value.
   * 
   * @param present
   *          The new value for the present flags of all attributes.
   */
  protected void setAllPresentFlags(boolean present) {
    // make a deep clone of all attributes
    Enumeration attributesEnumeration = attributeTable_.elements();
    while (attributesEnumeration.hasMoreElements()) {
      Attribute attribute = (Attribute) attributesEnumeration.nextElement();
      attribute.setPresent(present);
    }
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
    return toString(false, true, Constants.INDENT);
  }

  /**
   * This method returns a string representation of the current object. Some parameters can be set
   * to manipulate the output. The output is only for debugging purposes and should not be used for
   * other purposes.
   * 
   * @param newline
   *          true if the output should start in a new line
   * @param withName
   *          true if the type of the attribute should be returned too
   * @param indent
   *          the indent to be used
   * @return A string presentation of this object for debugging output.
   * 
   * @postconditions (result <> null)
   */
  public String toString(boolean newline, boolean withName, String indent) {
    StringBuffer buffer = new StringBuffer(1024);

    Enumeration attributesEnumeration = attributeTable_.elements();
    boolean firstAttribute = !newline;
    while (attributesEnumeration.hasMoreElements()) {
      Attribute attribute = (Attribute) attributesEnumeration.nextElement();
      if (attribute.isPresent()) {
        if (!firstAttribute) {
          buffer.append(Constants.NEWLINE);
        }
        buffer.append(indent);
        buffer.append(attribute.toString(withName));
        firstAttribute = false;
      }
    }

    return buffer.toString();
  }

}
