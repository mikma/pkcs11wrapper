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

package iaik.pkcs.pkcs11;

import iaik.pkcs.pkcs11.wrapper.CK_VERSION;

/**
 * Objects of this class represent a version. This consists of a major and a minor version number.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class Version implements Cloneable {

  /**
   * The major version number.
   */
  protected byte major_;

  /**
   * The minor version number.
   */
  protected byte minor_;

  /**
   * Constructor for internal use only.
   * 
   */
  protected Version() { /* left empty intentionally */
  }

  /**
   * Constructor taking a CK_VERSION object.
   * 
   * @param ckVersion
   *          A CK_VERSION object.
   * @preconditions (ckVersion <> null)
   * 
   */
  protected Version(CK_VERSION ckVersion) {
    if (ckVersion == null) {
      throw new NullPointerException("Argument \"ckVersion\" must not be null.");
    }
    major_ = ckVersion.major;
    minor_ = ckVersion.minor;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof Version) and (result.equals(this))
   */
  public java.lang.Object clone() {
    Version clone;

    try {
      clone = (Version) super.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get the major version number.
   * 
   * @return The major version number.
   */
  public byte getMajor() {
    return major_;
  }

  /**
   * Get the minor version number.
   * 
   * @return The minor version number.
   */
  public byte getMinor() {
    return minor_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of this object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(major_ & 0xff);
    buffer.append('.');
    if (minor_ < 10) {
      buffer.append('0');
    }
    buffer.append(minor_ & 0xff);

    return buffer.toString();
  }

  /**
   * Compares major and minor version number of this objects with the other object. Returns only
   * true, if both are equal in both objects.
   * 
   * @param otherObject
   *          The other Version object.
   * @return True, if other is an instance of Info and all member variables of both objects are
   *         equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof Version) {
      Version other = (Version) otherObject;
      equal = (this == other)
          || ((this.major_ == other.major_) && (this.minor_ == other.minor_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the slotID_, state_ and deviceError_.
   */
  public int hashCode() {
    return major_ ^ minor_;
  }

}
