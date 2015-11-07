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

package iaik.pkcs.pkcs11.parameters;

//import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.TokenRuntimeException;
import iaik.pkcs.pkcs11.wrapper.Constants;

/**
 * This class encapsulates parameters for Mechanisms.CONCATENATE_BASE_AND_KEY.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class ObjectHandleParameters implements Parameters {

  /**
   * The PKCS#11 object.
   */
  protected iaik.pkcs.pkcs11.objects.Object object_;

  /**
   * Create a new ObjectHandleParameters object using the given object.
   * 
   * @param object
   *          The PKCS#11 object which's handle to use.
   */
  public ObjectHandleParameters(iaik.pkcs.pkcs11.objects.Object object) {
    object_ = object;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof ObjectHandleParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    ObjectHandleParameters clone;

    try {
      clone = (ObjectHandleParameters) super.clone();

      clone.object_ = (iaik.pkcs.pkcs11.objects.Object) this.object_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get this parameters object as an Long object, which is the handle of the underlying object.
   * 
   * @return This object as a Long object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    return new Long(object_.getObjectHandle());
  }

  /**
   * Get the PKCS#11 object.
   * 
   * @return The PKCS#11 object.
   */
  public iaik.pkcs.pkcs11.objects.Object getObject() {
    return object_;
  }

  /**
   * Set the PKCS#11 object.
   * 
   * @param object
   *          The PKCS#11 object.
   */
  public void setObjectHandle(iaik.pkcs.pkcs11.objects.Object object) {
    object_ = object;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   * 
   * @return A string representation of this object.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(Constants.INDENT);
    buffer.append("The Object: ");
    buffer.append(Constants.NEWLINE);
    buffer.append(object_);
    // buffer.append(Constants.NEWLINE);

    return buffer.toString();
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

    if (otherObject instanceof ObjectHandleParameters) {
      ObjectHandleParameters other = (ObjectHandleParameters) otherObject;
      equal = (this == other) || ((this != null) && this.object_.equals(other.object_));
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
    return (object_ != null) ? object_.hashCode() : 0;
  }

}
