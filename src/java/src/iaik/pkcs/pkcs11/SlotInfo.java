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
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this call provide information about a slot. A slot can be a smart card reader, for
 * instancce. Notice that this object is immutable; i.e. it gets its state at object creation and
 * does not alter afterwards. Thus, all information this object provides, is a snapshot at the
 * object creation. This is especially important when calling isTokenPresent().
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (slotDescription_ <> null) and (manufacturerID_ <> null) and (hardwareVersion_ <>
 *             null) and (firmwareVersion_ <> null)
 */
public class SlotInfo {

  /**
   * A short descrption of this slot.
   */
  protected String slotDescription_;

  /**
   * A string identifying the manufacturer of this slot.
   */
  protected String manufacturerID_;

  /**
   * The version of the slot's hardware.
   */
  protected Version hardwareVersion_;

  /**
   * The version of the slot's firmware.
   */
  protected Version firmwareVersion_;

  /**
   * Indicates, if a token is present.
   */
  protected boolean tokenPresent_;

  /**
   * Indicates, if the token's in this slot are removable or not.
   */
  protected boolean removableDevice_;

  /**
   * Indicate, if this slot is a hardware device or if it is just pure software; i.e. no hardware
   * involved, e.g. a softtoken.
   */
  protected boolean hwSlot_;

  /**
   * Constructor that takes the CK_SLOT_INFO object as given by PKCS11.C_GetSlotInfo().
   * 
   * @param ckSlotInfo
   *          The CK_SLOT_INFO object as given by PKCS11.C_GetSlotInfo().
   * @preconditions (ckSlotInfo <> null)
   * 
   */
  protected SlotInfo(CK_SLOT_INFO ckSlotInfo) {
    if (ckSlotInfo == null) {
      throw new NullPointerException("Argument \"ckSlotInfo\" must not be null.");
    }
    slotDescription_ = new String(ckSlotInfo.slotDescription);
    manufacturerID_ = new String(ckSlotInfo.manufacturerID);
    hardwareVersion_ = new Version(ckSlotInfo.hardwareVersion);
    firmwareVersion_ = new Version(ckSlotInfo.firmwareVersion);
    tokenPresent_ = (ckSlotInfo.flags & PKCS11Constants.CKF_TOKEN_PRESENT) != 0L;
    removableDevice_ = (ckSlotInfo.flags & PKCS11Constants.CKF_REMOVABLE_DEVICE) != 0L;
    hwSlot_ = (ckSlotInfo.flags & PKCS11Constants.CKF_HW_SLOT) != 0L;
  }

  /**
   * Get a short description of this slot.
   * 
   * @return A string describing this slot.
   * 
   * @postconditions (result <> null)
   */
  public String getSlotDescription() {
    return slotDescription_;
  }

  /**
   * Get an identifier for the manufacturer of this slot.
   * 
   * @return A string identifying the manufacturer of this slot.
   * 
   * @postconditions (result <> null)
   */
  public String getManufacturerID() {
    return manufacturerID_;
  }

  /**
   * Get the verion of the slot's hardware.
   * 
   * @return The version of the hardware of this slot.
   * 
   * @postconditions (result <> null)
   */
  public Version getHardwareVersion() {
    return hardwareVersion_;
  }

  /**
   * Get the version of the slot's firmware.
   * 
   * @return The version of the firmware of this slot.
   * 
   * @postconditions (result <> null)
   */
  public Version getFirmwareVersion() {
    return firmwareVersion_;
  }

  /**
   * Indicates, if there is a token present in this slot. Notice, that this refers to the time this
   * object was created and not when this method is invoked.
   * 
   * @return True, if there is a (compatible) token in the slot. False, otherwise.
   */
  public boolean isTokenPresent() {
    return tokenPresent_;
  }

  /**
   * Indicate, if the token is removalbe from this slot or not. In some cases slot and token will be
   * one device.
   * 
   * @return True, if the tokens are removable. False, otherwise.
   */
  public boolean isRemovableDevice() {
    return removableDevice_;
  }

  /**
   * Indicate, if the token is a hardware device or if it is just a pure software implementation;
   * e.g. in case of a pure softwaretoken.
   * 
   * @return True, if it is a hardware slot. False, otherwise.
   */
  public boolean isHwSlot() {
    return hwSlot_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Slot Description: ");
    buffer.append(slotDescription_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Manufacturer ID: ");
    buffer.append(manufacturerID_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Hardware Version: ");
    buffer.append(hardwareVersion_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Firmware Version: ");
    buffer.append(firmwareVersion_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Token present: ");
    buffer.append(tokenPresent_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Removable Device: ");
    buffer.append(removableDevice_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Hardware Slot: ");
    buffer.append(hwSlot_);

    return buffer.toString();
  }

  /**
   * Compares all member variables of this object with the other object. Returns only true, if all
   * are equal in both objects.
   * 
   * @param otherObject
   *          The other SlotInfo object.
   * @return True, if other is an instance of Info and all member variables of both objects are
   *         equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof SlotInfo) {
      SlotInfo other = (SlotInfo) otherObject;
      equal = (this == other)
          || (this.slotDescription_.equals(other.slotDescription_)
              && this.manufacturerID_.equals(other.manufacturerID_)
              && this.hardwareVersion_.equals(other.hardwareVersion_)
              && this.firmwareVersion_.equals(other.firmwareVersion_)
              && (this.tokenPresent_ == other.tokenPresent_)
              && (this.removableDevice_ == other.removableDevice_) && (this.hwSlot_ == other.hwSlot_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the slotDescription_, manufacturerID_,
   *         hardwareVersion_ and firmwareVersion_.
   */
  public int hashCode() {
    return slotDescription_.hashCode() ^ manufacturerID_.hashCode()
        ^ hardwareVersion_.hashCode() ^ firmwareVersion_.hashCode();
  }

}
