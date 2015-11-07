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

import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class provide information about a certain mechanism that a token implements.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class MechanismInfo implements Cloneable {

  /**
   * The minimum key length supported by this algorithm.
   */
  protected long minKeySize_;

  /**
   * The maximum key length supported by this algorithm.
   */
  protected long maxKeySize_;

  /**
   * Contains all feature flags of this mechanism info.
   */
  protected long flags_;

  /**
   * Default constructor. All memeber variables get the defualt value for their tpye.
   * 
   */
  public MechanismInfo() { /* left empty intentionally */
  }

  /**
   * Constructor taking a CK_MECHANISM_INFO object as data source.
   * 
   * @param ckMechanismInfo
   *          The CK_MECHANISM_INFO object that provides the data.
   * @preconditions (ckMechanismInfo <> null)
   * 
   */
  public MechanismInfo(CK_MECHANISM_INFO ckMechanismInfo) {
    if (ckMechanismInfo == null) {
      throw new NullPointerException("Argument \"ckMechanismInfo\" must not be null.");
    }
    minKeySize_ = ckMechanismInfo.ulMinKeySize;
    maxKeySize_ = ckMechanismInfo.ulMaxKeySize;
    flags_ = ckMechanismInfo.flags;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof MechanismInfo) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    MechanismInfo clone;

    try {
      clone = (MechanismInfo) super.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new TokenRuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Override equals to check for the equality of mechanism infos.
   * 
   * @param otherObject
   *          The other MechanismInfo object.
   * @return True, if other is an instance of this class and all member variables are equal.
   */
  public boolean equals(Object otherObject) {
    boolean euqal = false;

    if (otherObject instanceof MechanismInfo) {
      MechanismInfo other = (MechanismInfo) otherObject;
      euqal = (this == other)
          || ((this.minKeySize_ == other.minKeySize_)
              && (this.maxKeySize_ == other.maxKeySize_) && (this.flags_ == other.flags_));
    }

    return euqal;
  }

  /**
   * Override hashCode to ensure that hashtable still works after overriding equals.
   * 
   * @return The hash code of this object. Taken from the mechanism code.
   */
  public int hashCode() {
    return (int) (minKeySize_ ^ maxKeySize_ ^ flags_);
  }

  /**
   * Get the minimum key length supported by this mechanism.
   * 
   * @return The minimum key length supported by this mechanism..
   */
  public long getMinKeySize() {
    return minKeySize_;
  }

  /**
   * Get the maximum key length supported by this mechanism.
   * 
   * @return The maximum key length supported by this mechanism.
   */
  public long getMaxKeySize() {
    return maxKeySize_;
  }

  /**
   * Check, if this mechanism is performed in hardware.
   * 
   * @return True, if this mechanism is performed in hardware.
   */
  public boolean isHw() {
    return (flags_ & PKCS11Constants.CKF_HW) != 0L;
  }

  /**
   * Check, if this mechanism can be used for encryption.
   * 
   * @return True, if this mechanism can be used for encrpytion.
   */
  public boolean isEncrypt() {
    return (flags_ & PKCS11Constants.CKF_ENCRYPT) != 0L;
  }

  /**
   * Check, if this mechanism can be used for decryption.
   * 
   * @return True, if this mechanism can be used for decrpytion.
   */
  public boolean isDecrypt() {
    return (flags_ & PKCS11Constants.CKF_DECRYPT) != 0L;
  }

  /**
   * Check, if this mechanism can be used for digesting.
   * 
   * @return True, if this mechanism can be used for digesting.
   */
  public boolean isDigest() {
    return (flags_ & PKCS11Constants.CKF_DIGEST) != 0L;
  }

  /**
   * Check, if this mechanism can be used for signing.
   * 
   * @return True, if this mechanism can be used for signing.
   */
  public boolean isSign() {
    return (flags_ & PKCS11Constants.CKF_SIGN) != 0L;
  }

  /**
   * Check, if this mechanism can be used for signing with data recovery.
   * 
   * @return True, if this mechanism can be used for signing with data recovery.
   */
  public boolean isSignRecover() {
    return (flags_ & PKCS11Constants.CKF_SIGN_RECOVER) != 0L;
  }

  /**
   * Check, if this mechanism can be used for verification.
   * 
   * @return True, if this mechanism can be used for verification.
   */
  public boolean isVerify() {
    return (flags_ & PKCS11Constants.CKF_VERIFY) != 0L;
  }

  /**
   * Check, if this mechanism can be used for verification with data recovery.
   * 
   * @return True, if this mechanism can be used for verification with data recovery.
   */
  public boolean isVerifyRecover() {
    return (flags_ & PKCS11Constants.CKF_VERIFY_RECOVER) != 0L;
  }

  /**
   * Check, if this mechanism can be used for secret key generation.
   * 
   * @return True, if this mechanism can be used for secret key generation.
   */
  public boolean isGenerate() {
    return (flags_ & PKCS11Constants.CKF_GENERATE) != 0L;
  }

  /**
   * Check, if this mechanism can be used for key-pair generation.
   * 
   * @return True, if this mechanism can be used for key-pair generation.
   */
  public boolean isGenerateKeyPair() {
    return (flags_ & PKCS11Constants.CKF_GENERATE_KEY_PAIR) != 0L;
  }

  /**
   * Check, if this mechanism can be used for key wrapping.
   * 
   * @return True, if this mechanism can be used for key wrapping.
   */
  public boolean isWrap() {
    return (flags_ & PKCS11Constants.CKF_WRAP) != 0L;
  }

  /**
   * Check, if this mechanism can be used for key unwrapping.
   * 
   * @return True, if this mechanism can be used for key unwrapping.
   */
  public boolean isUnwrap() {
    return (flags_ & PKCS11Constants.CKF_UNWRAP) != 0L;
  }

  /**
   * Check, if this mechanism can be used for key derivation.
   * 
   * @return True, if this mechanism can be used for key derivation.
   */
  public boolean isDerive() {
    return (flags_ & PKCS11Constants.CKF_DERIVE) != 0L;
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters over Fp.
   * 
   * @return True, if this mechanism can be used with EC domain parameters over Fp.
   */
  public boolean isEcFp() {
    return (flags_ & PKCS11Constants.CKF_EC_F_P) != 0L;
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters over F2m.
   * 
   * @return True, if this mechanism can be used with EC domain parameters over F2m.
   */
  public boolean isEcF2m() {
    return (flags_ & PKCS11Constants.CKF_EC_F_2M) != 0L;
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters of the choice ecParameters.
   * 
   * @return True, if this mechanism can be used with EC domain parameters of the choice
   *         ecParameters.
   */
  public boolean isEcEcParameters() {
    return (flags_ & PKCS11Constants.CKF_EC_ECPARAMETERS) != 0L;
  }

  /**
   * Check, if this mechanism can be used with EC domain parameters of the choice namedCurve.
   * 
   * @return True, if this mechanism can be used with EC domain parameters of the choice namedCurve.
   */
  public boolean isEcNamedCurve() {
    return (flags_ & PKCS11Constants.CKF_EC_NAMEDCURVE) != 0L;
  }

  /**
   * Check, if this mechanism can be used with elliptic curve point uncompressed.
   * 
   * @return True, if this mechanism can be used with elliptic curve point uncompressed.
   */
  public boolean isEcUncompress() {
    return (flags_ & PKCS11Constants.CKF_EC_UNCOMPRESS) != 0L;
  }

  /**
   * Check, if this mechanism can be used with elliptic curve point compressed.
   * 
   * @return True, if this mechanism can be used with elliptic curve point compressed.
   */
  public boolean isEcCompress() {
    return (flags_ & PKCS11Constants.CKF_EC_COMPRESS) != 0L;
  }

  /**
   * Check, if there is an extension to the flags; false, if no extensions. Must be false for this
   * version of PKCS#11.
   * 
   * @return False for this version.
   */
  public boolean isExtension() {
    return (flags_ & PKCS11Constants.CKF_EXTENSION) != 0L;
  }

  /**
   * Create a new MechanismInfo objects whichs flags are a logical OR of this object's flags and the
   * other object's flags. The minimum key size is set to the lower of both key sizes and the
   * maximum key size is set to the higher of both key sizes. If the other is null, the new object
   * has the same contents as this object.
   * 
   * @param other
   *          The other MechanismInfo object.
   * @return A new MechanismInfo that is a logical OR of this and other.
   */
  public MechanismInfo or(MechanismInfo other) {
    MechanismInfo result;

    if (other != null) {
      result = new MechanismInfo();
      result.flags_ = this.flags_ | other.flags_;
      result.minKeySize_ = (this.minKeySize_ < other.minKeySize_) ? this.minKeySize_
          : other.minKeySize_;
      result.maxKeySize_ = (this.maxKeySize_ > other.maxKeySize_) ? this.maxKeySize_
          : other.maxKeySize_;
    } else {
      result = (MechanismInfo) this.clone();
    }

    return result;
  }

  /**
   * Create a new MechanismInfo objects whichs flags are a logical AND of this object's flags and
   * the other object's flags. The minimum key size is set to the higher of both key sizes and the
   * maximum key size is set to the lower of both key sizes. If the other is null, the new object
   * has no flags set and its key sizes set to zero.
   * 
   * @param other
   *          The other MechanismInfo object.
   * @return A new MechanismInfo that is a logical AND of this and other.
   */
  public MechanismInfo and(MechanismInfo other) {
    MechanismInfo result = new MechanismInfo();

    if (other != null) {
      result.flags_ = this.flags_ & other.flags_;
      result.minKeySize_ = (this.minKeySize_ > other.minKeySize_) ? this.minKeySize_
          : other.minKeySize_;
      result.maxKeySize_ = (this.maxKeySize_ < other.maxKeySize_) ? this.maxKeySize_
          : other.maxKeySize_;
    }

    return result;
  }

  /**
   * Create a new MechanismInfo objects whichs flags are a logical NOT of this object's flags. The
   * key sizes remain the same.
   * 
   * @return A new MechanismInfo that is a logical NOT of this object.
   */
  public MechanismInfo not() {
    MechanismInfo result = (MechanismInfo) this.clone();

    result.flags_ = ~this.flags_;

    return result;
  }

  /**
   * Set the minimum key length supported by this mechanism.
   * 
   * @param minKeySize
   *          The minimum key length supported by this mechanism.
   */
  public void setMinKeySize(long minKeySize) {
    minKeySize_ = minKeySize;
  }

  /**
   * /** Set the maximum key length supported by this mechanism.
   * 
   * @param maxKeySize
   *          The maximum key length supported by this mechanism.
   */
  public void setMaxKeySize(long maxKeySize) {
    maxKeySize_ = maxKeySize;
  }

  /**
   * Set, if this mechanism is performed in hardware.
   * 
   * @param hw
   *          True, if this mechanism is performed in hardware.
   */
  public void setHw(boolean hw) {
    setFlagBit(PKCS11Constants.CKF_HW, hw);
  }

  /**
   * Set if this mechanism can be used for encryption.
   * 
   * @param encrypt
   *          True, if this mechanism can be used for encrpytion.
   */
  public void setEncrypt(boolean encrypt) {
    setFlagBit(PKCS11Constants.CKF_ENCRYPT, encrypt);
  }

  /**
   * Set if this mechanism can be used for decryption.
   * 
   * @param decrypt
   *          True, if this mechanism can be used for decrpytion.
   */
  public void setDecrypt(boolean decrypt) {
    setFlagBit(PKCS11Constants.CKF_DECRYPT, decrypt);
  }

  /**
   * Set if this mechanism can be used for digesting.
   * 
   * @param digest
   *          True, if this mechanism can be used for digesting.
   */
  public void setDigest(boolean digest) {
    setFlagBit(PKCS11Constants.CKF_DIGEST, digest);
  }

  /**
   * Set if this mechanism can be used for signing.
   * 
   * @param sign
   *          True, if this mechanism can be used for signing.
   */
  public void setSign(boolean sign) {
    setFlagBit(PKCS11Constants.CKF_SIGN, sign);
  }

  /**
   * Set if this mechanism can be used for signing with data recovery.
   * 
   * @param signRecover
   *          True, if this mechanism can be used for signing with data recovery.
   */
  public void setSignRecover(boolean signRecover) {
    setFlagBit(PKCS11Constants.CKF_SIGN_RECOVER, signRecover);
  }

  /**
   * Set if this mechanism can be used for verification.
   * 
   * @param verfy
   *          True, if this mechanism can be used for verification.
   */
  public void setVerify(boolean verfy) {
    setFlagBit(PKCS11Constants.CKF_VERIFY, verfy);
  }

  /**
   * Set if this mechanism can be used for verification with data recovery.
   * 
   * @param verifyRecover
   *          True, if this mechanism can be used for verification with data recovery.
   */
  public void setVerifyRecover(boolean verifyRecover) {
    setFlagBit(PKCS11Constants.CKF_VERIFY_RECOVER, verifyRecover);
  }

  /**
   * Set if this mechanism can be used for secret key generation.
   * 
   * @param generate
   *          True, if this mechanism can be used for secret key generation.
   */
  public void setGenerate(boolean generate) {
    setFlagBit(PKCS11Constants.CKF_GENERATE, generate);
  }

  /**
   * Set if this mechanism can be used for key-pair generation.
   * 
   * @param generateKeyPair
   *          True, if this mechanism can be used for key-pair generation.
   */
  public void setGenerateKeyPair(boolean generateKeyPair) {
    setFlagBit(PKCS11Constants.CKF_GENERATE_KEY_PAIR, generateKeyPair);
  }

  /**
   * Set if this mechanism can be used for key wrapping.
   * 
   * @param wrap
   *          True, if this mechanism can be used for key wrapping.
   */
  public void setWrap(boolean wrap) {
    setFlagBit(PKCS11Constants.CKF_WRAP, wrap);
  }

  /**
   * Set if this mechanism can be used for key unwrapping.
   * 
   * @param unwrap
   *          True, if this mechanism can be used for key unwrapping.
   */
  public void setUnwrap(boolean unwrap) {
    setFlagBit(PKCS11Constants.CKF_UNWRAP, unwrap);
  }

  /**
   * Set if this mechanism can be used for key derivation.
   * 
   * @param derive
   *          True, if this mechanism can be used for key derivation.
   */
  public void setDerive(boolean derive) {
    setFlagBit(PKCS11Constants.CKF_DERIVE, derive);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters over Fp.
   * 
   * @param ecFp
   *          True, if this mechanism can be used with EC domain parameters over Fp.
   */
  public void setEcFp(boolean ecFp) {
    setFlagBit(PKCS11Constants.CKF_EC_F_P, ecFp);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters over F2m.
   * 
   * @param ecF2m
   *          True, if this mechanism can be used with EC domain parameters over F2m.
   */
  public void setEcF2m(boolean ecF2m) {
    setFlagBit(PKCS11Constants.CKF_EC_F_2M, ecF2m);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters of the choice ecParameters.
   * 
   * @param ecEcParameters
   *          True, if this mechanism can be used with EC domain parameters of the choice
   *          ecParameters.
   */
  public void setEcEcParameters(boolean ecEcParameters) {
    setFlagBit(PKCS11Constants.CKF_EC_ECPARAMETERS, ecEcParameters);
  }

  /**
   * Set if this mechanism can be used with EC domain parameters of the choice namedCurve.
   * 
   * @param ecNamedCurve
   *          True, if this mechanism can be used with EC domain parameters of the choice
   *          namedCurve.
   */
  public void setEcNamedCurve(boolean ecNamedCurve) {
    setFlagBit(PKCS11Constants.CKF_EC_NAMEDCURVE, ecNamedCurve);
  }

  /**
   * Set if this mechanism can be used with elliptic curve point uncompressed.
   * 
   * @param ecUncompress
   *          True, if this mechanism can be used with elliptic curve point uncompressed.
   */
  public void setEcUncompress(boolean ecUncompress) {
    setFlagBit(PKCS11Constants.CKF_EC_UNCOMPRESS, ecUncompress);
  }

  /**
   * Set if this mechanism can be used with elliptic curve point compressed.
   * 
   * @param ecCompress
   *          True, if this mechanism can be used with elliptic curve point compressed.
   */
  public void setEcCompress(boolean ecCompress) {
    setFlagBit(PKCS11Constants.CKF_EC_COMPRESS, ecCompress);
  }

  /**
   * Set if there is an extension to the flags; false, if no extensions. Must be false for this
   * version.
   * 
   * @param extension
   *          False for this version.
   */
  public void setExtension(boolean extension) {
    setFlagBit(PKCS11Constants.CKF_EXTENSION, extension);
  }

  /**
   * Check, if this mechanism info has those flags set to true, which are set in the given mechanism
   * info. This may be used as a simple check, if some operations are supported. This also checks
   * the key length range, if they are specified in the given mechaism object; i.e. if they are not
   * zero.
   * 
   * @param requiredFeatures
   *          The required features.
   * @return True, if the required features are supported.
   * @preconditions (requiredFeatures <> null)
   * 
   */
  public boolean supports(MechanismInfo requiredFeatures) {
    if (requiredFeatures == null) {
      throw new NullPointerException("Argument \"requiredFeatures\" must not be null.");
    }

    long requiredMaxKeySize = requiredFeatures.getMaxKeySize();
    if ((requiredMaxKeySize != 0) && (requiredMaxKeySize > maxKeySize_)) {
      return false;
    }

    long requiredMinKeySize = requiredFeatures.getMinKeySize();
    if ((requiredMinKeySize != 0) && (requiredMinKeySize < minKeySize_)) {
      return false;
    }

    if ((requiredFeatures.flags_ & flags_) != requiredFeatures.flags_) {
      return false;
    }

    return true;
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of this object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer(256);

    buffer.append(Constants.INDENT);
    buffer.append("Minimum Key-Size: ");
    buffer.append(minKeySize_);

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Maximum Key-Size: ");
    buffer.append(maxKeySize_);

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Hardware: ");
    buffer.append(isHw());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Encrypt: ");
    buffer.append(isEncrypt());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Decrypt: ");
    buffer.append(isDecrypt());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Digest: ");
    buffer.append(isDigest());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Sign: ");
    buffer.append(isSign());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Sign Recover: ");
    buffer.append(isSignRecover());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Verify: ");
    buffer.append(isVerify());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Verify Recover: ");
    buffer.append(isVerifyRecover());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Generate: ");
    buffer.append(isGenerate());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Generate Key-Pair: ");
    buffer.append(isGenerateKeyPair());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Wrap: ");
    buffer.append(isWrap());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Unwrap: ");
    buffer.append(isUnwrap());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Derive: ");
    buffer.append(isDerive());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("EC F(p): ");
    buffer.append(isEcFp());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("EC F(2^m): ");
    buffer.append(isEcF2m());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("EC Parameters: ");
    buffer.append(isEcEcParameters());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("EC Named Curve: ");
    buffer.append(isEcNamedCurve());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("EC Uncompress: ");
    buffer.append(isEcUncompress());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("EC Compress: ");
    buffer.append(isEcCompress());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Extension: ");
    buffer.append(isExtension());

    return buffer.toString();
  }

  /**
   * Set the given feature flag(s) to the given value.
   * 
   * @param flagMask
   *          The mask of the flag bit(s).
   * @param value
   *          True to set the flag(s), false to clear the flag(s).
   */
  protected void setFlagBit(long flagMask, boolean value) {
    if (value) {
      flags_ |= flagMask;
    } else {
      flags_ &= ~flagMask;
    }
  }

}
