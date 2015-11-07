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

import iaik.pkcs.pkcs11.wrapper.CK_INFO;
import iaik.pkcs.pkcs11.wrapper.Constants;

/**
 * Objects of this class provide information about a PKCS#11 moduel; i.e. the driver for a spcific
 * token.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (cryptokiVersion_ <> null) and (manufacturerID_ <> null) and (libraryDescription_ <>
 *             null) and (libraryVersion_ <> null)
 */
public class Info implements Cloneable {

  /**
   * The module claims to be compliant to this version of PKCS#11.
   */
  protected Version cryptokiVersion_;

  /**
   * The identifer for the manufacturer of this module.
   */
  protected String manufacturerID_;

  /**
   * A description of this module.
   */
  protected String libraryDescription_;

  /**
   * The version number of this module.
   */
  protected Version libraryVersion_;

  /**
   * Constructor taking the CK_INFO object of the token.
   * 
   * @param ckInfo
   *          The info object as got from PKCS11.C_GetInfo().
   * @preconditions (ckInfo <> null)
   * 
   */
  protected Info(CK_INFO ckInfo) {
    if (ckInfo == null) {
      throw new NullPointerException("Argument \"ckInfo\" must not be null.");
    }
    cryptokiVersion_ = new Version(ckInfo.cryptokiVersion);
    manufacturerID_ = new String(ckInfo.manufacturerID);
    libraryDescription_ = new String(ckInfo.libraryDescription);
    libraryVersion_ = new Version(ckInfo.libraryVersion);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof Info) and (result.equals(this))
   */
  public java.lang.Object clone() {
    Info clone;

    try {
      clone = (Info) super.clone();

      clone.cryptokiVersion_ = (Version) this.cryptokiVersion_.clone();
      clone.libraryVersion_ = (Version) this.libraryVersion_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get the version of PKCS#11 that this module claims to be compliant to.
   * 
   * @return The version object.
   * 
   * @postconditions (result <> null)
   */
  public Version getCryptokiVersion() {
    return cryptokiVersion_;
  }

  /**
   * Get the identifier of the manufacturer.
   * 
   * @return A string identifying the manufacturer of this module.
   * 
   * @postconditions (result <> null)
   */
  public String getManufacturerID() {
    return manufacturerID_;
  }

  /**
   * Get a short descrption of this module.
   * 
   * @return A string describing the module.
   * 
   * @postconditions (result <> null)
   */
  public String getLibraryDescription() {
    return libraryDescription_;
  }

  /**
   * Get the version of this PKCS#11 module.
   * 
   * @return The version of this module.
   */
  public Version getLibraryVersion() {
    return libraryVersion_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Cryptoki Version: ");
    buffer.append(cryptokiVersion_);
    buffer.append(Constants.NEWLINE);

    buffer.append("ManufacturerID: ");
    buffer.append(manufacturerID_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Library Description: ");
    buffer.append(libraryDescription_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Library Version: ");
    buffer.append(libraryVersion_);

    return buffer.toString();
  }

  /**
   * Compares all member variables of this object with the other object. Returns only true, if all
   * are equal in both objects.
   * 
   * @param otherObject
   *          The other Info object.
   * @return True, if other is an instance of Info and all member variables of both objects are
   *         equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof Info) {
      Info other = (Info) otherObject;
      equal = (this == other)
          || (this.cryptokiVersion_.equals(other.cryptokiVersion_)
              && this.manufacturerID_.equals(other.manufacturerID_)
              && this.libraryDescription_.equals(other.libraryDescription_) && this.libraryVersion_
                .equals(other.libraryVersion_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from all member variables.
   */
  public int hashCode() {
    return cryptokiVersion_.hashCode() ^ manufacturerID_.hashCode()
        ^ libraryDescription_.hashCode() ^ libraryVersion_.hashCode();
  }

}
