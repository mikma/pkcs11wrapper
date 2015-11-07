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

import iaik.pkcs.pkcs11.wrapper.CK_SLOT_INFO;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;

/**
 * Objects of this class represent slots that can accept tokens. The application can get a token
 * object, if there is one present, by calling getToken. This may look like this:
 * 
 * <pre>
 * <code>
 *   Token token = slot.getToken();
 * 
 *   // to ensure that there is a token present in the slot
 *   if (token != null) {
 *     // ... work with the token
 *   }
 * </code>
 * </pre>
 * 
 * @see iaik.pkcs.pkcs11.SlotInfo
 * @see iaik.pkcs.pkcs11.Token
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (module_ <> null)
 */
public class Slot {

  /**
   * The module that created this slot object.
   */
  protected Module module_;

  /**
   * The identifier of the slot.
   */
  protected long slotID_;

  /**
   * True, if UTF8 encoding is used as character encoding for character array attributes and PINs.
   */
  protected boolean useUtf8Encoding_ = true;

  /**
   * The constructor that takes a reference to the module and the slot ID.
   * 
   * @param module
   *          The reference to the module of this slot.
   * @param slotID
   *          The identifier of the slot.
   * @preconditions (pkcs11Module <> null)
   * 
   */
  protected Slot(Module module, long slotID) {
    if (module == null) {
      throw new NullPointerException("Argument \"module\" must not be null.");
    }
    module_ = module;
    slotID_ = slotID;
  }

  /**
   * Compares the slot ID and the module_ of this object with the slot ID and module_ of the other
   * object. Returns only true, if both are equal.
   * 
   * @param otherObject
   *          The other Slot object.
   * @return True, if other is an instance of Slot and the slot ID and module_ of both objects are
   *         equal. False, otherwise.
   */
  public boolean equals(Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof Slot) {
      Slot other = (Slot) otherObject;
      equal = (this == other)
          || ((this.slotID_ == other.slotID_) && this.module_.equals(other.module_));
    }

    return equal;
  }

  /**
   * Specify, whether UTF8 character encoding shall be used for character array attributes and PINs.
   * 
   * @param useUtf8Encoding
   *          true, if UTF8 shall be used
   */
  public void setUtf8Encoding(boolean useUtf8Encoding) {
    useUtf8Encoding_ = useUtf8Encoding;
  }

  /**
   * Returns whether UTF8 encoding is set.
   * 
   * @return true, if UTF8 is used as character encoding for character array attributes and PINs.
   */
  public boolean isSetUtf8Encoding() {
    return useUtf8Encoding_;
  }

  /**
   * Get the module that created this Slot object.
   * 
   * @return The module of this slot.
   */
  public Module getModule() {
    return module_;
  }

  /**
   * Get the ID of this slot. This is the ID returned by the PKCS#11 module.
   * 
   * @return The ID of this slot.
   */
  public long getSlotID() {
    return slotID_;
  }

  /**
   * Get information about this slot object.
   * 
   * @return An object that contains informatin about this slot.
   * @exception TokenException
   *              If reading the information fails.
   * 
   * @postconditions (result <> null)
   */
  public SlotInfo getSlotInfo() throws TokenException {
    CK_SLOT_INFO ckSlotInfo = module_.getPKCS11Module().C_GetSlotInfo(slotID_);

    return new SlotInfo(ckSlotInfo);
  }

  /**
   * Get an object for handling the token that is currently present in this slot, or null, if there
   * is no token present.
   * 
   * @return The object for accessing the token. Or null, if none is present in this slot.
   * @exception TokenException
   *              If determining if a token is present fails.
   */
  public Token getToken() throws TokenException {
    Token token = null;

    if (getSlotInfo().isTokenPresent()) {
      token = new Token(this);
    }

    return token;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the slot ID.
   */
  public int hashCode() {
    return (int) slotID_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of this object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Slot ID: ");
    buffer.append("0x");
    buffer.append(Functions.toHexString(slotID_));
    buffer.append(Constants.NEWLINE);

    buffer.append("Module: ");
    buffer.append(module_.toString());

    return buffer.toString();
  }

}
