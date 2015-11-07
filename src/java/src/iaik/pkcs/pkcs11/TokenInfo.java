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

import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.util.Date;

/**
 * Objects of this class provide information about a token. Serial number, manufacturer, free
 * memory,... . Notice that this is just a snapshot of the token's status at the time this object
 * was created.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (label_ <> null) and (manufacturerID_ <> null) and (model_ <> null) and
 *             (serialNumber_ <> null) and (hardwareVersion_ <> null) and (firmwareVersion_ <> null)
 *             and (time_ <> null)
 */
public class TokenInfo implements Cloneable {

  /**
   * This is the value which can be used for ulMaxSessionCount and ulMaxRwSessionCount to express an
   * infinite number.
   */
  public static final long EFFECTIVELY_INFINITE = PKCS11Constants.CK_EFFECTIVELY_INFINITE;

  /**
   * This is the value which can be used for ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
   * ulRwSessionCount, ulTotalPublicMemory, ulFreePublicMemory, ulTotalPrivateMemory, and
   * ulFreePrivateMemory to signal that the information is unavailable.
   */
  public static final long UNAVAILABLE_INFORMATION = PKCS11Constants.CK_UNAVAILABLE_INFORMATION;

  /**
   * The label of this token.
   */
  protected String label_;

  /**
   * The identifier of the manufacturer of this token.
   */
  protected String manufacturerID_;

  /**
   * The model of this token.
   */
  protected String model_;

  /**
   * The serial number of this token.
   */
  protected String serialNumber_;

  /**
   * The maximum number of concurrent (open) sessions.
   */
  protected long maxSessionCount_;

  /**
   * The current number of open sessions.
   */
  protected long sessionCount_;

  /**
   * Maximum number of concurrent (open) read-write sessions.
   */
  protected long maxRwSessionCount_;

  /**
   * The current number of open read-write sessions.
   */
  protected long rwSessionCount_;

  /**
   * The maximum PIN length that this token allows.
   */
  protected long maxPinLen_;

  /**
   * The minimum PIN length that this token allows.
   */
  protected long minPinLen_;

  /**
   * The total amount of memory for public objects on this token.
   */
  protected long totalPublicMemory_;

  /**
   * The amount of free memory for public objects on this token.
   */
  protected long freePublicMemory_;

  /**
   * The total amount of memory for private objects on this token.
   */
  protected long totalPrivateMemory_;

  /**
   * The amount of free memory for private objects on this token.
   */
  protected long freePrivateMemory_;

  /**
   * The version of the hardware of this token.
   */
  protected Version hardwareVersion_;

  /**
   * The version of the firmware of this token.
   */
  protected Version firmwareVersion_;

  /**
   * The current time on the token. This value only makes sense, if the token contains a clock.
   */
  protected Date time_;

  /**
   * True, if the token has a random numebr generator.
   */
  protected boolean rng_;

  /**
   * True, if the token is write protected.
   */
  protected boolean writeProtected_;

  /**
   * True, if the token requires the user to login to perform certain operations.
   */
  protected boolean loginRequired_;

  /**
   * True, if the user-PIN is already initialized.
   */
  protected boolean userPinInitialized_;

  /**
   * True, if a successful save of a sessions cryptographic operations state always contains all
   * keys needed to restore the state of the session.
   */
  protected boolean restoreKeyNotNeeded_;

  /**
   * True, if the token has a clock.
   */
  protected boolean clockOnToken_;

  /**
   * True, if there are different means to authenticate the user than passing the user-PIN to a
   * login operation.
   */
  protected boolean protectedAuthenticationPath_;

  /**
   * True, if the token supports dual crypto operations.
   */
  protected boolean dualCryptoOperations_;

  /**
   * True, if the token is already initialized.
   */
  protected boolean tokenInitialized_;

  /**
   * True, if the token supports secondary authentication for private key objects.
   */
  protected boolean secondaryAuthentication_;

  /**
   * True, if the user-PIN has been entered incorrectly at least once since the last successful
   * authentication.
   */
  protected boolean userPinCountLow_;

  /**
   * True, if the user has just one try left to supply the correct PIN before the user-PIN gets
   * locked.
   */
  protected boolean userPinFinalTry_;

  /**
   * True, if the user-PIN is locked.
   */
  protected boolean userPinLocked_;

  /**
   * True, if the user PIN value is the default value set by token initialization or manufacturing.
   */
  protected boolean userPinToBeChanged_;

  /**
   * True, if the security officer-PIN has been entered incorrectly at least once since the last
   * successful authentication.
   */
  protected boolean soPinCountLow_;

  /**
   * True, if the security officer has just one try left to supply the correct PIN before the
   * security officer-PIN gets locked.
   */
  protected boolean soPinFinalTry_;

  /**
   * True, if the security officer-PIN is locked.
   */
  protected boolean soPinLocked_;

  /**
   * True, if the security officer-PIN value is the default value set by token initialization or
   * manufacturing.
   */
  protected boolean soPinToBeChanged_;

  /**
   * Constructor taking CK_TOKEN_INFO as given returned by PKCS11.C_GetTokenInfo.
   * 
   * @param ckTokenInfo
   *          The CK_TOKEN_INFO object as returned by PKCS11.C_GetTokenInfo.
   * @preconditions (ckTokenInfo <> null)
   * 
   */
  protected TokenInfo(CK_TOKEN_INFO ckTokenInfo) {
    if (ckTokenInfo == null) {
      throw new NullPointerException("Argument \"ckTokenInfo\" must not be null.");
    }
    label_ = new String(ckTokenInfo.label);
    manufacturerID_ = new String(ckTokenInfo.manufacturerID);
    model_ = new String(ckTokenInfo.model);
    serialNumber_ = new String(ckTokenInfo.serialNumber);
    maxSessionCount_ = ckTokenInfo.ulMaxSessionCount;
    sessionCount_ = ckTokenInfo.ulSessionCount;
    maxRwSessionCount_ = ckTokenInfo.ulMaxRwSessionCount;
    rwSessionCount_ = ckTokenInfo.ulRwSessionCount;
    maxPinLen_ = ckTokenInfo.ulMaxPinLen;
    minPinLen_ = ckTokenInfo.ulMinPinLen;
    totalPublicMemory_ = ckTokenInfo.ulTotalPublicMemory;
    freePublicMemory_ = ckTokenInfo.ulFreePublicMemory;
    totalPrivateMemory_ = ckTokenInfo.ulTotalPrivateMemory;
    freePrivateMemory_ = ckTokenInfo.ulFreePrivateMemory;
    hardwareVersion_ = new Version(ckTokenInfo.hardwareVersion);
    firmwareVersion_ = new Version(ckTokenInfo.firmwareVersion);
    time_ = Util.parseTime(ckTokenInfo.utcTime);
    rng_ = (ckTokenInfo.flags & PKCS11Constants.CKF_RNG) != 0L;
    writeProtected_ = (ckTokenInfo.flags & PKCS11Constants.CKF_WRITE_PROTECTED) != 0L;
    loginRequired_ = (ckTokenInfo.flags & PKCS11Constants.CKF_LOGIN_REQUIRED) != 0L;
    userPinInitialized_ = (ckTokenInfo.flags & PKCS11Constants.CKF_USER_PIN_INITIALIZED) != 0L;
    restoreKeyNotNeeded_ = (ckTokenInfo.flags & PKCS11Constants.CKF_RESTORE_KEY_NOT_NEEDED) != 0L;
    clockOnToken_ = (ckTokenInfo.flags & PKCS11Constants.CKF_CLOCK_ON_TOKEN) != 0L;
    protectedAuthenticationPath_ = (ckTokenInfo.flags & PKCS11Constants.CKF_PROTECTED_AUTHENTICATION_PATH) != 0L;
    dualCryptoOperations_ = (ckTokenInfo.flags & PKCS11Constants.CKF_DUAL_CRYPTO_OPERATIONS) != 0L;
    tokenInitialized_ = (ckTokenInfo.flags & PKCS11Constants.CKF_TOKEN_INITIALIZED) != 0L;
    secondaryAuthentication_ = (ckTokenInfo.flags & PKCS11Constants.CKF_SECONDARY_AUTHENTICATION) != 0L;
    userPinCountLow_ = (ckTokenInfo.flags & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L;
    userPinFinalTry_ = (ckTokenInfo.flags & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L;
    userPinLocked_ = (ckTokenInfo.flags & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L;
    userPinToBeChanged_ = (ckTokenInfo.flags & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L;
    soPinCountLow_ = (ckTokenInfo.flags & PKCS11Constants.CKF_SO_PIN_COUNT_LOW) != 0L;
    soPinFinalTry_ = (ckTokenInfo.flags & PKCS11Constants.CKF_SO_PIN_FINAL_TRY) != 0L;
    soPinLocked_ = (ckTokenInfo.flags & PKCS11Constants.CKF_SO_PIN_LOCKED) != 0L;
    soPinToBeChanged_ = (ckTokenInfo.flags & PKCS11Constants.CKF_SO_PIN_TO_BE_CHANGED) != 0L;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof TokenInfo) and (result.equals(this))
   */
  public java.lang.Object clone() {
    TokenInfo clone;

    try {
      clone = (TokenInfo) super.clone();

      clone.hardwareVersion_ = (Version) this.hardwareVersion_.clone();
      clone.firmwareVersion_ = (Version) this.firmwareVersion_.clone();
      clone.time_ = new Date(this.time_.getTime()); // clone() unsupported in JDK 1.1
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Get the label of this token.
   * 
   * @return The label of this token.
   * 
   * @postconditions (result <> null)
   */
  public String getLabel() {
    return label_;
  }

  /**
   * Get the manufacturer identifier.
   * 
   * @return A string identifying the manufacturer of this token.
   * 
   * @postconditions (result <> null)
   */
  public String getManufacturerID() {
    return manufacturerID_;
  }

  /**
   * Get the model of this token.
   * 
   * @return A string specifying the model of this token.
   * 
   * @postconditions (result <> null)
   */
  public String getModel() {
    return model_;
  }

  /**
   * Get the serial number of this token.
   * 
   * @return A string holding the serial number of this token.
   * 
   * @postconditions (result <> null)
   */
  public String getSerialNumber() {
    return serialNumber_;
  }

  /**
   * Get the maximum allowed number of (open) concurrent sessions.
   * 
   * @return The maximum allowed number of (open) concurrent sessions.
   */
  public long getMaxSessionCount() {
    return maxSessionCount_;
  }

  /**
   * Get the current number of open sessions.
   * 
   * @return The current number of open sessions.
   */
  public long getSessionCount() {
    return sessionCount_;
  }

  /**
   * Get the maximum allowed number of (open) concurrent read-write sessions.
   * 
   * @return The maximum allowed number of (open) concurrent read-write sessions.
   */
  public long getMaxRwSessionCount() {
    return maxRwSessionCount_;
  }

  /**
   * Get the current number of open read-write sessions.
   * 
   * @return The current number of open read-write sessions.
   */
  public long getRwSessionCount() {
    return rwSessionCount_;
  }

  /**
   * Get the maximum length for the PIN.
   * 
   * @return The maximum length for the PIN.
   */
  public long getMaxPinLen() {
    return maxPinLen_;
  }

  /**
   * Get the minimum length for the PIN.
   * 
   * @return The minimum length for the PIN.
   */
  public long getMinPinLen() {
    return minPinLen_;
  }

  /**
   * Get the total amount of memory for public objects.
   * 
   * @return The total amount of memory for public objects.
   */
  public long getTotalPublicMemory() {
    return totalPublicMemory_;
  }

  /**
   * Get the amount of free memory for public objects.
   * 
   * @return The amount of free memory for public objects.
   */
  public long getFreePublicMemory() {
    return freePublicMemory_;
  }

  /**
   * Get the total amount of memory for private objects.
   * 
   * @return The total amount of memory for private objects.
   */
  public long getTotalPrivateMemory() {
    return totalPrivateMemory_;
  }

  /**
   * Get the amount of free memory for private objects.
   * 
   * @return The amount of free memory for private objects.
   */
  public long getFreePrivateMemory() {
    return freePrivateMemory_;
  }

  /**
   * Get the version of the token's hardware.
   * 
   * @return The version of the token's hardware.
   * 
   * @postconditions (result <> null)
   */
  public Version getHardwareVersion() {
    return hardwareVersion_;
  }

  /**
   * Get the version of the token's firmware.
   * 
   * @return The version of the token's firmware.
   * 
   * @postconditions (result <> null)
   */
  public Version getFirmwareVersion() {
    return firmwareVersion_;
  }

  /**
   * Get the current time of the token's clock. This value does only make sense if the token has a
   * clock. Remind that, this is the time this object was created and not the time the application
   * called this method.
   * 
   * @return The current time on the token's clock.
   * @see #isClockOnToken()
   * 
   * @postconditions (result <> null)
   */
  public Date getTime() {
    return time_;
  }

  /**
   * Check, if the token has a random number generator.
   * 
   * @return True, if the token has a random number generator. False, otherwise.
   */
  public boolean isRNG() {
    return rng_;
  }

  /**
   * Check, if the token is write protected.
   * 
   * @return True, if the token is write protected. False, otherwise.
   */
  public boolean isWriteProtected() {
    return writeProtected_;
  }

  /**
   * Check, if the token requires the user to log in before certain operations can be performed.
   * 
   * @return True, if the token requires the user to log in before certain operations can be
   *         performed. False, otherwise.
   */
  public boolean isLoginRequired() {
    return loginRequired_;
  }

  /**
   * Check, if the user-PIN is already initialized.
   * 
   * @return True, if the user-PIN is already initialized. False, otherwise.
   */
  public boolean isUserPinInitialized() {
    return userPinInitialized_;
  }

  /**
   * Check, if a successful save of a sessions cryptographic operations state always contains all
   * keys needed to restore the state of the session.
   * 
   * @return True, if a successful save of a sessions cryptographic operations state always
   *         contains all keys needed to restore the state of the session. False, otherwise.
   */
  public boolean isRestoreKeyNotNeeded() {
    return restoreKeyNotNeeded_;
  }

  /**
   * Check, if the token has an own clock.
   * 
   * @return True, if the token has its own clock. False, otherwise.
   */
  public boolean isClockOnToken() {
    return clockOnToken_;
  }

  /**
   * Check, if the token has an protected authentication path. This means that a user may log in
   * without providing a PIN to the login method, because the token has other means to authenticate
   * the user; e.g. a PIN-pad on the reader or some biometric authentication.
   * 
   * @return True, if the token has an protected authentication path. False, otherwise.
   */
  public boolean isProtectedAuthenticationPath() {
    return protectedAuthenticationPath_;
  }

  /**
   * Check, if the token supports dual crypto operations.
   * 
   * @return True, if the token supports dual crypto operations. False, otherwise.
   */
  public boolean isDualCryptoOperations() {
    return dualCryptoOperations_;
  }

  /**
   * Check, if the token is already initialized.
   * 
   * @return True, if the token is already initialized. False, otherwise.
   */
  public boolean isTokenInitialized() {
    return tokenInitialized_;
  }

  /**
   * Check, if the token supports secondary authentication for private key objects.
   * 
   * @return True, if the token supports secondary authentication. False, otherwise.
   */
  public boolean isSecondaryAuthentication() {
    return secondaryAuthentication_;
  }

  /**
   * Check, if the user-PIN has been entered incorrectly at least once since the last successful
   * authentication.
   * 
   * @return True, if the the user-PIN has been entered incorrectly at least one since the last
   *         successful authentication. False, otherwise.
   */
  public boolean isUserPinCountLow() {
    return userPinCountLow_;
  }

  /**
   * Check, if the user has just one try left to supply the correct PIN before the user-PIN gets
   * locked.
   * 
   * @return True, if the user has just one try left to supply the correct PIN before the user-PIN
   *         gets locked. False, otherwise.
   */
  public boolean isUserPinFinalTry() {
    return userPinFinalTry_;
  }

  /**
   * Check, if the user-PIN is locked.
   * 
   * @return True, if the user-PIN is locked. False, otherwise.
   */
  public boolean isUserPinLocked() {
    return userPinLocked_;
  }

  /**
   * Check, if the user PIN value is the default value set by token initialization or manufacturing.
   * 
   * @return True, if the user PIN value is the default value set by token initialization or
   *         manufacturing. False, otherwise.
   */
  public boolean isUserPinToBeChanged() {
    return userPinToBeChanged_;
  }

  /**
   * Check, if the security officer-PIN has been entered incorrectly at least once since the last
   * successful authentication.
   * 
   * @return True, if the the security officer-PIN has been entered incorrectly at least one since
   *         the last successful authentication. False, otherwise.
   */
  public boolean isSoPinCountLow() {
    return soPinCountLow_;
  }

  /**
   * Check, if the security officer has just one try left to supply the correct PIN before the
   * security officer-PIN gets locked.
   * 
   * @return True, if the security officer has just one try left to supply the correct PIN before
   *         the security officer-PIN gets locked. False, otherwise.
   */
  public boolean isSoPinFinalTry() {
    return soPinFinalTry_;
  }

  /**
   * Check, if the security officer-PIN is locked.
   * 
   * @return True, if the security officer-PIN is locked. False, otherwise.
   */
  public boolean isSoPinLocked() {
    return soPinLocked_;
  }

  /**
   * Check, if the security officer PIN value is the default value set by token initialization or
   * manufacturing.
   * 
   * @return True, if the security officer PIN value is the default value set by token
   *         initialization or manufacturing. False, otherwise.
   */
  public boolean isSoPinToBeChanged() {
    return soPinToBeChanged_;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Label: ");
    buffer.append(label_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Manufacturer ID: ");
    buffer.append(manufacturerID_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Model: ");
    buffer.append(model_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Serial Number: ");
    buffer.append(serialNumber_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Random Number Generator: ");
    buffer.append(rng_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Write protected: ");
    buffer.append(writeProtected_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Login required: ");
    buffer.append(loginRequired_);

    buffer.append(Constants.NEWLINE);
    buffer.append("User PIN initialized: ");
    buffer.append(userPinInitialized_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Restore Key not needed: ");
    buffer.append(restoreKeyNotNeeded_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Clock on Token: ");
    buffer.append(clockOnToken_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Protected Authentication Path: ");
    buffer.append(protectedAuthenticationPath_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Dual Crypto Operations: ");
    buffer.append(dualCryptoOperations_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Token initialized: ");
    buffer.append(tokenInitialized_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Secondary Authentication: ");
    buffer.append(secondaryAuthentication_);

    buffer.append(Constants.NEWLINE);
    buffer.append("User PIN-Count low: ");
    buffer.append(userPinCountLow_);

    buffer.append(Constants.NEWLINE);
    buffer.append("User PIN final Try: ");
    buffer.append(userPinFinalTry_);

    buffer.append(Constants.NEWLINE);
    buffer.append("User PIN locked: ");
    buffer.append(userPinLocked_);

    buffer.append(Constants.NEWLINE);
    buffer.append("User PIN to be changed: ");
    buffer.append(userPinToBeChanged_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Security Officer PIN-Count low: ");
    buffer.append(soPinCountLow_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Security Officer PIN final Try: ");
    buffer.append(soPinFinalTry_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Security Officer PIN locked: ");
    buffer.append(soPinLocked_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Security Officer PIN to be changed: ");
    buffer.append(soPinToBeChanged_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Maximum Session Count: ");
    buffer
        .append((maxSessionCount_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : (maxSessionCount_ == EFFECTIVELY_INFINITE) ? "<effectively infinite>"
                : Long.toString(maxSessionCount_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Session Count: ");
    buffer
        .append((sessionCount_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : Long.toString(sessionCount_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Maximum Read/Write Session Count: ");
    buffer
        .append((maxRwSessionCount_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : (maxRwSessionCount_ == EFFECTIVELY_INFINITE) ? "<effectively infinite>"
                : Long.toString(maxRwSessionCount_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Read/Write Session Count: ");
    buffer
        .append((rwSessionCount_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : Long.toString(rwSessionCount_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Maximum PIN Length: ");
    buffer.append(maxPinLen_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Minimum PIN Length: ");
    buffer.append(minPinLen_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Total Public Memory: ");
    buffer
        .append((totalPublicMemory_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : Long.toString(totalPublicMemory_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Free Public Memory: ");
    buffer
        .append((freePublicMemory_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : Long.toString(freePublicMemory_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Total Private Memory: ");
    buffer
        .append((totalPrivateMemory_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : Long.toString(totalPrivateMemory_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Free Private Memory: ");
    buffer
        .append((freePrivateMemory_ == UNAVAILABLE_INFORMATION) ? "<Information unavailable>"
            : Long.toString(freePrivateMemory_));

    buffer.append(Constants.NEWLINE);
    buffer.append("Hardware Version: ");
    buffer.append(hardwareVersion_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Firmware Version: ");
    buffer.append(firmwareVersion_);

    buffer.append(Constants.NEWLINE);
    buffer.append("Time: ");
    buffer.append(time_);

    return buffer.toString();
  }

  /**
   * Compares all member variables of this object with the other object. Returns only true, if all
   * are equal in both objects.
   * 
   * @param otherObject
   *          The other TokenInfo object.
   * @return True, if other is an instance of Info and all member variables of both objects are
   *         equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof TokenInfo) {
      TokenInfo other = (TokenInfo) otherObject;
      equal = (this == other)
          || (this.label_.equals(other.label_)
              && this.manufacturerID_.equals(other.manufacturerID_)
              && this.model_.equals(other.model_)
              && this.serialNumber_.equals(other.serialNumber_)
              && (this.maxSessionCount_ == other.maxSessionCount_)
              && (this.sessionCount_ == other.sessionCount_)
              && (this.maxRwSessionCount_ == other.maxRwSessionCount_)
              && (this.rwSessionCount_ == other.rwSessionCount_)
              && (this.maxPinLen_ == other.maxPinLen_)
              && (this.minPinLen_ == other.minPinLen_)
              && (this.totalPublicMemory_ == other.totalPublicMemory_)
              && (this.freePublicMemory_ == other.freePublicMemory_)
              && (this.totalPrivateMemory_ == other.totalPrivateMemory_)
              && (this.freePrivateMemory_ == other.freePrivateMemory_)
              && this.hardwareVersion_.equals(other.hardwareVersion_)
              && this.firmwareVersion_.equals(other.firmwareVersion_)
              && this.time_.equals(other.time_)
              && (this.rng_ == other.rng_)
              && (this.writeProtected_ == other.writeProtected_)
              && (this.loginRequired_ == other.loginRequired_)
              && (this.userPinInitialized_ == other.userPinInitialized_)
              && (this.restoreKeyNotNeeded_ == other.restoreKeyNotNeeded_)
              && (this.clockOnToken_ == other.clockOnToken_)
              && (this.protectedAuthenticationPath_ == other.protectedAuthenticationPath_)
              && (this.dualCryptoOperations_ == other.dualCryptoOperations_)
              && (this.tokenInitialized_ == other.tokenInitialized_)
              && (this.secondaryAuthentication_ == other.secondaryAuthentication_)
              && (this.userPinCountLow_ == other.userPinCountLow_)
              && (this.userPinFinalTry_ == other.userPinFinalTry_)
              && (this.userPinLocked_ == other.userPinLocked_)
              && (this.userPinToBeChanged_ == other.userPinToBeChanged_)
              && (this.soPinCountLow_ == other.soPinCountLow_)
              && (this.soPinFinalTry_ == other.soPinFinalTry_)
              && (this.soPinLocked_ == other.soPinLocked_) && (this.soPinToBeChanged_ == other.soPinToBeChanged_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the label_, manufacturerID_, model_ and
   *         serialNumber_.
   */
  public int hashCode() {
    return label_.hashCode() ^ manufacturerID_.hashCode() ^ model_.hashCode()
        ^ serialNumber_.hashCode();
  }

}
