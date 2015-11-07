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

import iaik.pkcs.pkcs11.wrapper.CK_SESSION_INFO;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * An object of this class provides information about a session. The information provided is just a
 * snapshot at the time this information object was created; it does not retrieve the information
 * from the session on demand.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (state_ <> null)
 */
public class SessionInfo implements Cloneable {

  /**
   * The identifier of the slot in which the token resides this session is bound to.
   */
  protected long slotID_;

  /**
   * The current session state.
   */
  protected State state_;

  /**
   * An token specific error-code. The meaning of this value is not defined in PKCS#11.
   */
  protected long deviceError_;

  /**
   * True, if this is a read-write session.
   */
  protected boolean rwSession_;

  /**
   * True, if this a serial session. Always true, for this version of PKCS#11.
   */
  protected boolean serialSession_;

  /**
   * Constructor taking a CK_SESSION_INFO object that provides the infromation.
   * 
   * @param ckSessionInfo
   *          The object providing the session information.
   * @preconditions (pkcs11Module <> null) and (ckSessionInfo <> null)
   * 
   */
  protected SessionInfo(CK_SESSION_INFO ckSessionInfo) {
    if (ckSessionInfo == null) {
      throw new NullPointerException("Argument \"ckSessionInfo\" must not be null.");
    }
    slotID_ = ckSessionInfo.slotID;
    state_ = new State(ckSessionInfo.state);
    deviceError_ = ckSessionInfo.ulDeviceError;
    rwSession_ = (ckSessionInfo.flags & PKCS11Constants.CKF_RW_SESSION) != 0L;
    serialSession_ = (ckSessionInfo.flags & PKCS11Constants.CKF_SERIAL_SESSION) != 0L;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof SessionInfo) and (result.equals(this))
   */
  public java.lang.Object clone() {
    SessionInfo clone;

    try {
      clone = (SessionInfo) super.clone();

      clone.state_ = (State) this.state_.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get the current state of this session.
   * 
   * @return The current state of this session.
   * 
   * @postconditions (result <> null)
   */
  public State getState() {
    return state_;
  }

  /**
   * Get the current device error-code of the token. Notice that this code is device-specific. Its
   * meaning is not defined in the PKCS#11 standard.
   * 
   * @return The error-code of the device.
   */
  public long getDeviceError() {
    return deviceError_;
  }

  /**
   * Check, if this is a read-write session.
   * 
   * @return True, if this is a read-write session; false, if this is a read-only session.
   */
  public boolean isRwSession() {
    return rwSession_;
  }

  /**
   * Check, if this is a serial session. Should always be true for version 2.x of the PKCS#11
   * standard.
   * 
   * @return True, if this is a serial session; flase, if this is a parallel session. Should always
   *         be true for version 2.x of the PKCS#11 standard..
   */
  public boolean isSerialSession() {
    return serialSession_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return The string representation of object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("State: ");
    buffer.append(state_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Device Error: 0x");
    buffer.append(Functions.toHexString(deviceError_));
    buffer.append(Constants.NEWLINE);

    buffer.append("Read/Write Session: ");
    buffer.append(rwSession_);
    buffer.append(Constants.NEWLINE);

    buffer.append("Serial Session: ");
    buffer.append(serialSession_);

    return buffer.toString();
  }

  /**
   * Compares all member variables of this object with the other object. Returns only true, if all
   * are equal in both objects.
   * 
   * @param otherObject
   *          The other SessionInfo object.
   * @return True, if other is an instance of Info and all member variables of both objects are
   *         equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof SessionInfo) {
      SessionInfo other = (SessionInfo) otherObject;
      equal = (this == other)
          || ((this.slotID_ == other.slotID_) && this.state_.equals(other.state_)
              && (this.deviceError_ == other.deviceError_)
              && (this.rwSession_ == other.rwSession_) && (this.serialSession_ == other.serialSession_));
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
    return ((int) slotID_) ^ state_.hashCode() ^ ((int) deviceError_);
  }

}
