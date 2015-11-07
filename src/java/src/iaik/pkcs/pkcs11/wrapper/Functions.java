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

package iaik.pkcs.pkcs11.wrapper;

import java.math.BigInteger;
import java.util.Hashtable;

/**
 * This class contains onyl static methods. It is the place for all functions that are used by
 * several classes in this package.
 * 
 * @author Karl Scheibelhofer
 * @author Martin Schläffer
 */
public class Functions {

  /**
   * Maps mechanism codes as Long to their names as Strings.
   */
  protected static Hashtable mechansimNames_;

  /**
   * This table contains the mechanisms that are full encrypt/decrypt mechanisms; i.e. mechanisms
   * that support the update functoins. The Long values of the mechanisms are the keys, and the
   * mechanism names are the values.
   */
  protected static Hashtable fullEncryptDecryptMechanisms_;

  /**
   * This table contains the mechanisms that are single-operation encrypt/decrypt mechanisms; i.e.
   * mechanisms that do not support the update functoins. The Long values of the mechanisms are the
   * keys, and the mechanism names are the values.
   */
  protected static Hashtable singleOperationEncryptDecryptMechanisms_;

  /**
   * This table contains the mechanisms that are full sign/verify mechanisms; i.e. mechanisms that
   * support the update functoins. The Long values of the mechanisms are the keys, and the mechanism
   * names are the values.
   */
  protected static Hashtable fullSignVerifyMechanisms_;

  /**
   * This table contains the mechanisms that are single-operation sign/verify mechanisms; i.e.
   * mechanisms that do not support the update functoins. The Long values of the mechanisms are the
   * keys, and the mechanism names are the values.
   */
  protected static Hashtable singleOperationSignVerifyMechanisms_;

  /**
   * This table contains the mechanisms that are sign/verify mechanisms with message recovery. The
   * Long values of the mechanisms are the keys, and the mechanism names are the values.
   */
  protected static Hashtable signVerifyRecoverMechanisms_;

  /**
   * This table contains the mechanisms that are digest mechanisms. The Long values of the
   * mechanisms are the keys, and the mechanism names are the values.
   */
  protected static Hashtable digestMechanisms_;

  /**
   * This table contains the mechanisms that key generation mechanisms; i.e. mechanisms for
   * generating symmetric keys. The Long values of the mechanisms are the keys, and the mechanism
   * names are the values.
   */
  protected static Hashtable keyGenerationMechanisms_;

  /**
   * This table contains the mechanisms that key-pair generation mechanisms; i.e. mechanisms for
   * generating key-pairs. The Long values of the mechanisms are the keys, and the mechanism names
   * are the values.
   */
  protected static Hashtable keyPairGenerationMechanisms_;

  /**
   * This table contains the mechanisms that are wrap/unwrap mechanisms. The Long values of the
   * mechanisms are the keys, and the mechanism names are the values.
   */
  protected static Hashtable wrapUnwrapMechanisms_;

  /**
   * This table contains the mechanisms that are key derivation mechanisms. The Long values of the
   * mechanisms are the keys, and the mechanism names are the values.
   */
  protected static Hashtable keyDerivationMechanisms_;

  /**
   * For converting numbers to their hex presentation.
   */
  protected static final char HEX_DIGITS[] = { '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

  /**
   * Converts a long value to a hexadecimal String of length 16. Includes leading zeros if
   * necessary.
   * 
   * @param value
   *          The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toFullHexString(long value) {
    long currentValue = value;
    StringBuffer stringBuffer = new StringBuffer(16);
    for (int j = 0; j < 16; j++) {
      int currentDigit = (int) currentValue & 0xf;
      stringBuffer.append(HEX_DIGITS[currentDigit]);
      currentValue >>>= 4;
    }

    return stringBuffer.reverse().toString();
  }

  /**
   * Converts a int value to a hexadecimal String of length 8. Includes leading zeros if necessary.
   * 
   * @param value
   *          The int value to be converted.
   * @return The hexadecimal string representation of the int value.
   */
  public static String toFullHexString(int value) {
    int currentValue = value;
    StringBuffer stringBuffer = new StringBuffer(8);
    for (int i = 0; i < 8; i++) {
      int currentDigit = currentValue & 0xf;
      stringBuffer.append(HEX_DIGITS[currentDigit]);
      currentValue >>>= 4;
    }

    return stringBuffer.reverse().toString();
  }

  /**
   * Converts a long value to a hexadecimal String.
   * 
   * @param value
   *          The long value to be converted.
   * @return The hexadecimal string representation of the long value.
   */
  public static String toHexString(long value) {
    return Long.toHexString(value);
  }

  /**
   * Converts a byte array to a hexadecimal String. Each byte is presented by its two digit
   * hex-code; 0x0A -> "0a", 0x00 -> "00". No leading "0x" is included in the result.
   * 
   * @param value
   *          the byte array to be converted
   * @return the hexadecimal string representation of the byte array
   */
  public static String toHexString(byte[] value) {
    if (value == null) {
      return null;
    }

    StringBuffer buffer = new StringBuffer(2 * value.length);
    int single;

    for (int i = 0; i < value.length; i++) {
      single = value[i] & 0xFF;

      if (single < 0x10) {
        buffer.append('0');
      }

      buffer.append(Integer.toString(single, 16));
    }

    return buffer.toString();
  }

  /**
   * Converts a long value to a binary String.
   * 
   * @param value
   *          the long value to be converted.
   * @return the binary string representation of the long value.
   */
  public static String toBinaryString(long value) {
    return Long.toString(value, 2);
  }

  /**
   * Converts a byte array to a binary String.
   * 
   * @param value
   *          The byte array to be converted.
   * @return The binary string representation of the byte array.
   */
  public static String toBinaryString(byte[] value) {
    BigInteger helpBigInteger = new BigInteger(1, value);

    return helpBigInteger.toString(2);
  }

  /**
   * Converts the long value flags to a SlotInfoFlag string.
   * 
   * @param flags
   *          The flags to be converted.
   * @return The SlotInfoFlag string representation of the flags.
   */
  public static String slotInfoFlagsToString(long flags) {
    StringBuffer buffer = new StringBuffer();
    boolean notFirst = false;

    if ((flags & PKCS11Constants.CKF_TOKEN_PRESENT) != 0L) {
      buffer.append("CKF_TOKEN_PRESENT");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_REMOVABLE_DEVICE) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_TOKEN_PRESENT");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_HW_SLOT) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_HW_SLOT");
    }

    return buffer.toString();
  }

  /**
   * Converts long value flags to a TokenInfoFlag string.
   * 
   * @param flags
   *          The flags to be converted.
   * @return The TokenInfoFlag string representation of the flags.
   */
  public static String tokenInfoFlagsToString(long flags) {
    StringBuffer buffer = new StringBuffer();
    boolean notFirst = false;

    if ((flags & PKCS11Constants.CKF_RNG) != 0L) {
      buffer.append("CKF_RNG");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_WRITE_PROTECTED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_WRITE_PROTECTED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_LOGIN_REQUIRED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_LOGIN_REQUIRED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_USER_PIN_INITIALIZED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_INITIALIZED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_RESTORE_KEY_NOT_NEEDED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_RESTORE_KEY_NOT_NEEDED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_CLOCK_ON_TOKEN) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_CLOCK_ON_TOKEN");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_PROTECTED_AUTHENTICATION_PATH) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_PROTECTED_AUTHENTICATION_PATH");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_DUAL_CRYPTO_OPERATIONS) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_DUAL_CRYPTO_OPERATIONS");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_TOKEN_INITIALIZED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_TOKEN_INITIALIZED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SECONDARY_AUTHENTICATION) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_SECONDARY_AUTHENTICATION");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_USER_PIN_COUNT_LOW) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_COUNT_LOW");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_USER_PIN_FINAL_TRY) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_FINAL_TRY");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_USER_PIN_LOCKED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_LOCKED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_USER_PIN_TO_BE_CHANGED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_TO_BE_CHANGED");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SO_PIN_COUNT_LOW) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_SO_PIN_COUNT_LOW");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SO_PIN_FINAL_TRY) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_SO_PIN_FINAL_TRY");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SO_PIN_LOCKED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_FINAL_TRY");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SO_PIN_TO_BE_CHANGED) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_USER_PIN_LOCKED");

      notFirst = true;
    }

    return buffer.toString();
  }

  /**
   * Converts the long value flags to a SessionInfoFlag string.
   * 
   * @param flags
   *          The flags to be converted.
   * @return The SessionInfoFlag string representation of the flags.
   */
  public static String sessionInfoFlagsToString(long flags) {
    StringBuffer buffer = new StringBuffer();
    boolean notFirst = false;

    if ((flags & PKCS11Constants.CKF_RW_SESSION) != 0L) {
      buffer.append("CKF_RW_SESSION");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SERIAL_SESSION) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_SERIAL_SESSION");
    }

    return buffer.toString();
  }

  /**
   * Converts the long value state to a SessionState string.
   * 
   * @param state
   *          The state to be converted.
   * @return The SessionState string representation of the state.
   */
  public static String sessionStateToString(long state) {
    String name;

    if (state == PKCS11Constants.CKS_RO_PUBLIC_SESSION) {
      name = "CKS_RO_PUBLIC_SESSION";
    } else if (state == PKCS11Constants.CKS_RO_USER_FUNCTIONS) {
      name = "CKS_RO_USER_FUNCTIONS";
    } else if (state == PKCS11Constants.CKS_RW_PUBLIC_SESSION) {
      name = "CKS_RW_PUBLIC_SESSION";
    } else if (state == PKCS11Constants.CKS_RW_USER_FUNCTIONS) {
      name = "CKS_RW_USER_FUNCTIONS";
    } else if (state == PKCS11Constants.CKS_RW_SO_FUNCTIONS) {
      name = "CKS_RW_SO_FUNCTIONS";
    } else {
      name = "ERROR: unknown session state 0x" + toFullHexString(state);
    }

    return name;
  }

  /**
   * Converts the long value flags to a MechanismInfoFlag string.
   * 
   * @param flags
   *          The flags to be converted to a string representation.
   * @return The MechanismInfoFlag string representation of the flags.
   */
  public static String mechanismInfoFlagsToString(long flags) {
    StringBuffer buffer = new StringBuffer();
    boolean notFirst = false;

    if ((flags & PKCS11Constants.CKF_HW) != 0L) {
      buffer.append("CKF_HW");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_ENCRYPT) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_ENCRYPT");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_DECRYPT) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_DECRYPT");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_DIGEST) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_DIGEST");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SIGN) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_SIGN");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_SIGN_RECOVER) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_SIGN_RECOVER");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_VERIFY) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_VERIFY");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_VERIFY_RECOVER) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_VERIFY_RECOVER");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_GENERATE) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_GENERATE");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_GENERATE_KEY_PAIR) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_GENERATE_KEY_PAIR");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_WRAP) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_WRAP");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_UNWRAP) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_UNWRAP");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_DERIVE) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_DERIVE");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EC_F_P) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EC_F_P");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EC_F_2M) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EC_F_2M");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EC_ECPARAMETERS) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EC_ECPARAMETERS");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EC_NAMEDCURVE) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EC_NAMEDCURVE");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EC_UNCOMPRESS) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EC_UNCOMPRESS");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EC_COMPRESS) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EC_COMPRESS");

      notFirst = true;
    }

    if ((flags & PKCS11Constants.CKF_EXTENSION) != 0L) {
      if (notFirst) {
        buffer.append(" | ");
      }

      buffer.append("CKF_EXTENSION");

      notFirst = true;
    }

    return buffer.toString();
  }

  /**
   * Converts the long value code of a mechanism to a name.
   * 
   * @param mechansimCode
   *          The code of the mechanism to be converted to a string.
   * @return The string representation of the mechanism.
   */
  public static String mechanismCodeToString(long mechansimCode) {
    if (mechansimNames_ == null) {
      Hashtable mechansimNames = new Hashtable(200);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_RSA_PKCS_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_9796),
          PKCS11Constants.NAME_CKM_RSA_9796);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_X_509),
          PKCS11Constants.NAME_CKM_RSA_X_509);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD2_RSA_PKCS),
          PKCS11Constants.NAME_CKM_MD2_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD5_RSA_PKCS),
          PKCS11Constants.NAME_CKM_MD5_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA1_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA1_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD128_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RIPEMD128_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD160_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RIPEMD160_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_PKCS_OAEP),
          PKCS11Constants.NAME_CKM_RSA_PKCS_OAEP);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_RSA_X9_31_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_X9_31),
          PKCS11Constants.NAME_CKM_RSA_X9_31);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA1_RSA_X9_31),
          PKCS11Constants.NAME_CKM_SHA1_RSA_X9_31);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_RSA_PKCS_PSS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA1_RSA_PKCS_PSS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_DSA_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DSA), PKCS11Constants.NAME_CKM_DSA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DSA_SHA1),
          PKCS11Constants.NAME_CKM_DSA_SHA1);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DH_PKCS_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_DH_PKCS_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DH_PKCS_DERIVE),
          PKCS11Constants.NAME_CKM_DH_PKCS_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_X9_42_DH_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_X9_42_DH_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_X9_42_DH_DERIVE),
          PKCS11Constants.NAME_CKM_X9_42_DH_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_X9_42_DH_HYBRID_DERIVE),
          PKCS11Constants.NAME_CKM_X9_42_DH_HYBRID_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_X9_42_MQV_DERIVE),
          PKCS11Constants.NAME_CKM_X9_42_MQV_DERIVE);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA256_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA256_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA384_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA384_RSA_PKCS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA512_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA512_RSA_PKCS);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA256_RSA_PKCS_PSS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA384_RSA_PKCS_PSS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA512_RSA_PKCS_PSS);

      mechansimNames.put(new Long(PKCS11Constants.CKM_RC2_KEY_GEN),
          PKCS11Constants.NAME_CKM_RC2_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC2_ECB),
          PKCS11Constants.NAME_CKM_RC2_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC2_CBC),
          PKCS11Constants.NAME_CKM_RC2_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC2_MAC),
          PKCS11Constants.NAME_CKM_RC2_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC2_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_RC2_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC2_CBC_PAD),
          PKCS11Constants.NAME_CKM_RC2_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC4_KEY_GEN),
          PKCS11Constants.NAME_CKM_RC4_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC4), PKCS11Constants.NAME_CKM_RC4);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_KEY_GEN),
          PKCS11Constants.NAME_CKM_DES_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_ECB),
          PKCS11Constants.NAME_CKM_DES_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_CBC),
          PKCS11Constants.NAME_CKM_DES_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_MAC),
          PKCS11Constants.NAME_CKM_DES_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_DES_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_CBC_PAD),
          PKCS11Constants.NAME_CKM_DES_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES2_KEY_GEN),
          PKCS11Constants.NAME_CKM_DES2_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_KEY_GEN),
          PKCS11Constants.NAME_CKM_DES3_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_ECB),
          PKCS11Constants.NAME_CKM_DES3_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_CBC),
          PKCS11Constants.NAME_CKM_DES3_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_MAC),
          PKCS11Constants.NAME_CKM_DES3_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_DES3_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_CBC_PAD),
          PKCS11Constants.NAME_CKM_DES3_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CDMF_KEY_GEN),
          PKCS11Constants.NAME_CKM_CDMF_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CDMF_ECB),
          PKCS11Constants.NAME_CKM_CDMF_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CDMF_CBC),
          PKCS11Constants.NAME_CKM_CDMF_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CDMF_MAC),
          PKCS11Constants.NAME_CKM_CDMF_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CDMF_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CDMF_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CDMF_CBC_PAD),
          PKCS11Constants.NAME_CKM_CDMF_CBC_PAD);

      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_OFB64),
          PKCS11Constants.NAME_CKM_DES_OFB64);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_OFB8),
          PKCS11Constants.NAME_CKM_DES_OFB8);

      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_CFB64),
          PKCS11Constants.NAME_CKM_DES_CFB64);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_CFB8),
          PKCS11Constants.NAME_CKM_DES_CFB8);

      mechansimNames.put(new Long(PKCS11Constants.CKM_MD2), PKCS11Constants.NAME_CKM_MD2);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD2_HMAC),
          PKCS11Constants.NAME_CKM_MD2_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD2_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_MD2_HMAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD5), PKCS11Constants.NAME_CKM_MD5);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD5_HMAC),
          PKCS11Constants.NAME_CKM_MD5_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD5_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_MD5_HMAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA_1),
          PKCS11Constants.NAME_CKM_SHA_1);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA_1_HMAC),
          PKCS11Constants.NAME_CKM_SHA_1_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA_1_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA_1_HMAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD128),
          PKCS11Constants.NAME_CKM_RIPEMD128);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD128_HMAC),
          PKCS11Constants.NAME_CKM_RIPEMD128_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD128_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_RIPEMD128_HMAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD160),
          PKCS11Constants.NAME_CKM_RIPEMD160);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD160_HMAC),
          PKCS11Constants.NAME_CKM_RIPEMD160_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RIPEMD160_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_RIPEMD160_HMAC_GENERAL);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA256),
          PKCS11Constants.NAME_CKM_SHA256);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA256_HMAC),
          PKCS11Constants.NAME_CKM_SHA256_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA256_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA256_HMAC_GENERAL);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA384),
          PKCS11Constants.NAME_CKM_SHA384);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA384_HMAC),
          PKCS11Constants.NAME_CKM_SHA384_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA384_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA384_HMAC_GENERAL);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA512),
          PKCS11Constants.NAME_CKM_SHA512);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA512_HMAC),
          PKCS11Constants.NAME_CKM_SHA512_HMAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA512_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA512_HMAC_GENERAL);

      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST_ECB),
          PKCS11Constants.NAME_CKM_CAST_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST_CBC),
          PKCS11Constants.NAME_CKM_CAST_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST_MAC),
          PKCS11Constants.NAME_CKM_CAST_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST3_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST3_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST3_ECB),
          PKCS11Constants.NAME_CKM_CAST3_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST3_CBC),
          PKCS11Constants.NAME_CKM_CAST3_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST3_MAC),
          PKCS11Constants.NAME_CKM_CAST3_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST3_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST3_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST3_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST3_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST5_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST5_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST128_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST128_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST5_ECB),
          PKCS11Constants.NAME_CKM_CAST5_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST128_ECB),
          PKCS11Constants.NAME_CKM_CAST128_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST5_CBC),
          PKCS11Constants.NAME_CKM_CAST5_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST128_CBC),
          PKCS11Constants.NAME_CKM_CAST128_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST5_MAC),
          PKCS11Constants.NAME_CKM_CAST5_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST128_MAC),
          PKCS11Constants.NAME_CKM_CAST128_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST5_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST5_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST128_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST128_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST5_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST5_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CAST128_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST128_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC5_KEY_GEN),
          PKCS11Constants.NAME_CKM_RC5_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC5_ECB),
          PKCS11Constants.NAME_CKM_RC5_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC5_CBC),
          PKCS11Constants.NAME_CKM_RC5_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC5_MAC),
          PKCS11Constants.NAME_CKM_RC5_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC5_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_RC5_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_RC5_CBC_PAD),
          PKCS11Constants.NAME_CKM_RC5_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_IDEA_KEY_GEN),
          PKCS11Constants.NAME_CKM_IDEA_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_IDEA_ECB),
          PKCS11Constants.NAME_CKM_IDEA_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_IDEA_CBC),
          PKCS11Constants.NAME_CKM_IDEA_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_IDEA_MAC),
          PKCS11Constants.NAME_CKM_IDEA_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_IDEA_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_IDEA_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_IDEA_CBC_PAD),
          PKCS11Constants.NAME_CKM_IDEA_CBC_PAD);
      mechansimNames.put(new Long(PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN),
          PKCS11Constants.NAME_CKM_GENERIC_SECRET_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY),
          PKCS11Constants.NAME_CKM_CONCATENATE_BASE_AND_KEY);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CONCATENATE_BASE_AND_DATA),
          PKCS11Constants.NAME_CKM_CONCATENATE_BASE_AND_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_CONCATENATE_DATA_AND_BASE),
          PKCS11Constants.NAME_CKM_CONCATENATE_DATA_AND_BASE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_XOR_BASE_AND_DATA),
          PKCS11Constants.NAME_CKM_XOR_BASE_AND_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY),
          PKCS11Constants.NAME_CKM_EXTRACT_KEY_FROM_KEY);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SSL3_PRE_MASTER_KEY_GEN),
          PKCS11Constants.NAME_CKM_SSL3_PRE_MASTER_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_SSL3_MASTER_KEY_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_SSL3_KEY_AND_MAC_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE_DH),
          PKCS11Constants.NAME_CKM_SSL3_MASTER_KEY_DERIVE_DH);
      mechansimNames.put(new Long(PKCS11Constants.CKM_TLS_PRE_MASTER_KEY_GEN),
          PKCS11Constants.NAME_CKM_TLS_PRE_MASTER_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_TLS_MASTER_KEY_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_TLS_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_TLS_KEY_AND_MAC_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE_DH),
          PKCS11Constants.NAME_CKM_TLS_MASTER_KEY_DERIVE_DH);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SSL3_MD5_MAC),
          PKCS11Constants.NAME_CKM_SSL3_MD5_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SSL3_SHA1_MAC),
          PKCS11Constants.NAME_CKM_SSL3_SHA1_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD5_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_MD5_KEY_DERIVATION);
      mechansimNames.put(new Long(PKCS11Constants.CKM_MD2_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_MD2_KEY_DERIVATION);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA1_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA1_KEY_DERIVATION);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA256_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA256_KEY_DERIVATION);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA384_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA384_KEY_DERIVATION);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SHA512_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA512_KEY_DERIVATION);

      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_MD2_DES_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD2_DES_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_MD5_DES_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_DES_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST3_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST3_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST5_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST5_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST128_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST128_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_CAST5_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_CAST5_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_CAST128_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_CAST128_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC4_128),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC4_128);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC4_40),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC4_40);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_DES3_EDE_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_DES3_EDE_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_DES2_EDE_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_DES2_EDE_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC2_128_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC2_128_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC2_40_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC2_40_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PKCS5_PBKD2),
          PKCS11Constants.NAME_CKM_PKCS5_PBKD2);
      mechansimNames.put(new Long(PKCS11Constants.CKM_PBA_SHA1_WITH_SHA1_HMAC),
          PKCS11Constants.NAME_CKM_PBA_SHA1_WITH_SHA1_HMAC);

      mechansimNames.put(new Long(PKCS11Constants.CKM_WTLS_PRE_MASTER_KEY_GEN),
          PKCS11Constants.NAME_CKM_WTLS_PRE_MASTER_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_WTLS_MASTER_KEY_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC),
          PKCS11Constants.NAME_CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_WTLS_PRF),
          PKCS11Constants.NAME_CKM_WTLS_PRF);
      mechansimNames.put(new Long(PKCS11Constants.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE);

      mechansimNames.put(new Long(PKCS11Constants.CKM_KEY_WRAP_LYNKS),
          PKCS11Constants.NAME_CKM_KEY_WRAP_LYNKS);
      mechansimNames.put(new Long(PKCS11Constants.CKM_KEY_WRAP_SET_OAEP),
          PKCS11Constants.NAME_CKM_KEY_WRAP_SET_OAEP);

      mechansimNames.put(new Long(PKCS11Constants.CKM_CMS_SIG),
          PKCS11Constants.NAME_CKM_CMS_SIG);

      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_KEY_GEN),
          PKCS11Constants.NAME_CKM_SKIPJACK_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_ECB64),
          PKCS11Constants.NAME_CKM_SKIPJACK_ECB64);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_CBC64),
          PKCS11Constants.NAME_CKM_SKIPJACK_CBC64);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_OFB64),
          PKCS11Constants.NAME_CKM_SKIPJACK_OFB64);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB64),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB64);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB32),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB32);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB16),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB16);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB8),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB8);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_WRAP),
          PKCS11Constants.NAME_CKM_SKIPJACK_WRAP);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_PRIVATE_WRAP),
          PKCS11Constants.NAME_CKM_SKIPJACK_PRIVATE_WRAP);
      mechansimNames.put(new Long(PKCS11Constants.CKM_SKIPJACK_RELAYX),
          PKCS11Constants.NAME_CKM_SKIPJACK_RELAYX);
      mechansimNames.put(new Long(PKCS11Constants.CKM_KEA_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_KEA_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_KEA_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_KEA_KEY_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_FORTEZZA_TIMESTAMP),
          PKCS11Constants.NAME_CKM_FORTEZZA_TIMESTAMP);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_KEY_GEN),
          PKCS11Constants.NAME_CKM_BATON_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_ECB128),
          PKCS11Constants.NAME_CKM_BATON_ECB128);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_ECB96),
          PKCS11Constants.NAME_CKM_BATON_ECB96);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_CBC128),
          PKCS11Constants.NAME_CKM_BATON_CBC128);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_COUNTER),
          PKCS11Constants.NAME_CKM_BATON_COUNTER);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_SHUFFLE),
          PKCS11Constants.NAME_CKM_BATON_SHUFFLE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BATON_WRAP),
          PKCS11Constants.NAME_CKM_BATON_WRAP);
      mechansimNames.put(new Long(PKCS11Constants.CKM_ECDSA_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_ECDSA_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_EC_KEY_PAIR_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_ECDSA),
          PKCS11Constants.NAME_CKM_ECDSA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_ECDSA_SHA1),
          PKCS11Constants.NAME_CKM_ECDSA_SHA1);
      mechansimNames.put(new Long(PKCS11Constants.CKM_ECDH1_DERIVE),
          PKCS11Constants.NAME_CKM_ECDH1_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_ECDH1_COFACTOR_DERIVE),
          PKCS11Constants.NAME_CKM_ECDH1_COFACTOR_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_ECMQV_DERIVE),
          PKCS11Constants.NAME_CKM_ECMQV_DERIVE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_JUNIPER_KEY_GEN),
          PKCS11Constants.NAME_CKM_JUNIPER_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_JUNIPER_ECB128),
          PKCS11Constants.NAME_CKM_JUNIPER_ECB128);
      mechansimNames.put(new Long(PKCS11Constants.CKM_JUNIPER_CBC128),
          PKCS11Constants.NAME_CKM_JUNIPER_CBC128);
      mechansimNames.put(new Long(PKCS11Constants.CKM_JUNIPER_COUNTER),
          PKCS11Constants.NAME_CKM_JUNIPER_COUNTER);
      mechansimNames.put(new Long(PKCS11Constants.CKM_JUNIPER_SHUFFLE),
          PKCS11Constants.NAME_CKM_JUNIPER_SHUFFLE);
      mechansimNames.put(new Long(PKCS11Constants.CKM_JUNIPER_WRAP),
          PKCS11Constants.NAME_CKM_JUNIPER_WRAP);
      mechansimNames.put(new Long(PKCS11Constants.CKM_FASTHASH),
          PKCS11Constants.NAME_CKM_FASTHASH);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_KEY_GEN),
          PKCS11Constants.NAME_CKM_AES_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_ECB),
          PKCS11Constants.NAME_CKM_AES_ECB);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_CBC),
          PKCS11Constants.NAME_CKM_AES_CBC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_MAC),
          PKCS11Constants.NAME_CKM_AES_MAC);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_AES_MAC_GENERAL);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_CBC_PAD),
          PKCS11Constants.NAME_CKM_AES_CBC_PAD);

      mechansimNames.put(new Long(PKCS11Constants.CKM_BLOWFISH_KEY_GEN),
          PKCS11Constants.NAME_CKM_BLOWFISH_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_BLOWFISH_CBC),
          PKCS11Constants.NAME_CKM_BLOWFISH_CBC);

      mechansimNames.put(new Long(PKCS11Constants.CKM_TWOFISH_KEY_GEN),
          PKCS11Constants.NAME_CKM_TWOFISH_KEY_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_TWOFISH_CBC),
          PKCS11Constants.NAME_CKM_TWOFISH_CBC);

      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES_ECB_ENCRYPT_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES_CBC_ENCRYPT_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES3_ECB_ENCRYPT_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES3_CBC_ENCRYPT_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_AES_ECB_ENCRYPT_DATA);
      mechansimNames.put(new Long(PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_AES_CBC_ENCRYPT_DATA);

      mechansimNames.put(new Long(PKCS11Constants.CKM_DSA_PARAMETER_GEN),
          PKCS11Constants.NAME_CKM_DSA_PARAMETER_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_DH_PKCS_PARAMETER_GEN),
          PKCS11Constants.NAME_CKM_DH_PKCS_PARAMETER_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_X9_42_DH_PARAMETER_GEN),
          PKCS11Constants.NAME_CKM_X9_42_DH_PARAMETER_GEN);
      mechansimNames.put(new Long(PKCS11Constants.CKM_VENDOR_DEFINED),
          PKCS11Constants.NAME_CKM_VENDOR_DEFINED);
      mechansimNames_ = mechansimNames;
    }

    Long mechansimCodeObject = new Long(mechansimCode);
    Object entry = mechansimNames_.get(mechansimCodeObject);

    String mechanismName = (entry != null) ? entry.toString()
        : "Unknwon mechanism with code: 0x" + toFullHexString(mechansimCode);

    return mechanismName;
  }

  /**
   * Converts the long value classType to a string representation of it.
   * 
   * @param classType
   *          The classType to be converted.
   * @return The string representation of the classType.
   */
  public static String classTypeToString(long classType) {
    String name;

    if (classType == PKCS11Constants.CKO_DATA) {
      name = "CKO_DATA";
    } else if (classType == PKCS11Constants.CKO_CERTIFICATE) {
      name = "CKO_CERTIFICATE";
    } else if (classType == PKCS11Constants.CKO_PUBLIC_KEY) {
      name = "CKO_PUBLIC_KEY";
    } else if (classType == PKCS11Constants.CKO_PRIVATE_KEY) {
      name = "CKO_PRIVATE_KEY";
    } else if (classType == PKCS11Constants.CKO_SECRET_KEY) {
      name = "CKO_SECRET_KEY";
    } else if (classType == PKCS11Constants.CKO_HW_FEATURE) {
      name = "CKO_HW_FEATURE";
    } else if (classType == PKCS11Constants.CKO_DOMAIN_PARAMETERS) {
      name = "CKO_DOMAIN_PARAMETERS";
    } else if (classType == PKCS11Constants.CKO_VENDOR_DEFINED) {
      name = "CKO_VENDOR_DEFINED";
    } else {
      name = "ERROR: unknown classType with code: 0x" + toFullHexString(classType);
    }

    return name;
  }

  /**
   * Check the given arrays for equalitiy. This method considers both arrays as equal, if both are
   * <code>null</code> or both have the same length and contain exactly the same byte values.
   * 
   * @param array1
   *          The first array.
   * @param array2
   *          The second array.
   * @return True, if both arrays are <code>null</code> or both have the same length and contain
   *         exactly the same byte values. False, otherwise.
   */
  public static boolean equals(byte[] array1, byte[] array2) {
    boolean equal = false;

    if (array1 == array2) {
      equal = true;
    } else if ((array1 != null) && (array2 != null)) {
      int length = array1.length;
      if (length == array2.length) {
        equal = true;
        for (int i = 0; i < length; i++) {
          if (array1[i] != array2[i]) {
            equal = false;
            break;
          }
        }
      } else {
        equal = false;
      }
    } else {
      equal = false;
    }

    return equal;
  }

  /**
   * Check the given arrays for equalitiy. This method considers both arrays as equal, if both are
   * <code>null</code> or both have the same length and contain exactly the same char values.
   * 
   * @param array1
   *          The first array.
   * @param array2
   *          The second array.
   * @return True, if both arrays are <code>null</code> or both have the same length and contain
   *         exactly the same char values. False, otherwise.
   */
  public static boolean equals(char[] array1, char[] array2) {
    boolean equal = false;

    if (array1 == array2) {
      equal = true;
    } else if ((array1 != null) && (array2 != null)) {
      int length = array1.length;
      if (length == array2.length) {
        equal = true;
        for (int i = 0; i < length; i++) {
          if (array1[i] != array2[i]) {
            equal = false;
            break;
          }
        }
      } else {
        equal = false;
      }
    } else {
      equal = false;
    }

    return equal;
  }

  /**
   * Check the given arrays for equality. This method considers both arrays as equal, if both are
   * <code>null</code> or both have the same length and contain exactly the same byte values.
   * 
   * @param array1
   *          The first array.
   * @param array2
   *          The second array.
   * @return True, if both arrays are <code>null</code> or both have the same length and contain
   *         exactly the same byte values. False, otherwise.
   */
  public static boolean equals(long[] array1, long[] array2) {
    boolean equal = false;

    if (array1 == array2) {
      equal = true;
    } else if ((array1 != null) && (array2 != null)) {
      int length = array1.length;
      if (length == array2.length) {
        equal = true;
        for (int i = 0; i < length; i++) {
          if (array1[i] != array2[i]) {
            equal = false;
            break;
          }
        }
      } else {
        equal = false;
      }
    } else {
      equal = false;
    }

    return equal;
  }

  /**
   * Check the given dates for equalitiy. This method considers both dates as equal, if both are
   * <code>null</code> or both contain exactly the same char values.
   * 
   * @param date1
   *          The first date.
   * @param date2
   *          The second date.
   * @return True, if both dates are <code>null</code> or both contain the same char values. False,
   *         otherwise.
   */
  public static boolean equals(CK_DATE date1, CK_DATE date2) {
    boolean equal = false;

    if (date1 == date2) {
      equal = true;
    } else if ((date1 != null) && (date2 != null)) {
      equal = equals(date1.year, date2.year) && equals(date1.month, date2.month)
          && equals(date1.day, date2.day);
    } else {
      equal = false;
    }

    return equal;
  }

  /**
   * Calculate a hash code for the given byte array.
   * 
   * @param array
   *          The byte array.
   * @return A hash code for the given array.
   */
  public static int hashCode(byte[] array) {
    int hash = 0;

    if (array != null) {
      for (int i = 0; (i < 4) && (i < array.length); i++) {
        hash ^= (0xFF & array[i]) << ((i % 4) << 3);
      }
    }

    return hash;
  }

  /**
   * Calculate a hash code for the given char array.
   * 
   * @param array
   *          The char array.
   * @return A hash code for the given array.
   */
  public static int hashCode(char[] array) {
    int hash = 0;

    if (array != null) {
      for (int i = 0; (i < 4) && (i < array.length); i++) {
        // hash ^= (0xFFFFFFFF & (array[i]>>32)); // this is useless since char is 16bit wide
        hash ^= (0xFFFFFFFF & array[i]);
      }
    }

    return hash;
  }

  /**
   * Calculate a hash code for the given long array.
   * 
   * @param array
   *          The long array.
   * @return A hash code for the given array.
   */
  public static int hashCode(long[] array) {
    int hash = 0;

    if (array != null) {
      for (int i = 0; (i < 4) && (i < array.length); i++) {
        hash ^= (0xFFFFFFFF & (array[i] >> 4));
        hash ^= (0xFFFFFFFF & array[i]);
      }
    }

    return hash;
  }

  /**
   * Calculate a hash code for the given date object.
   * 
   * @param date
   *          The date object.
   * @return A hash code for the given date.
   */
  public static int hashCode(CK_DATE date) {
    int hash = 0;

    if (date != null) {
      if (date.year.length == 4) {
        hash ^= (0xFFFF & date.year[0]) << 16;
        hash ^= 0xFFFF & date.year[1];
        hash ^= (0xFFFF & date.year[2]) << 16;
        hash ^= 0xFFFF & date.year[3];
      }
      if (date.month.length == 2) {
        hash ^= (0xFFFF & date.month[0]) << 16;
        hash ^= 0xFFFF & date.month[1];
      }
      if (date.day.length == 2) {
        hash ^= (0xFFFF & date.day[0]) << 16;
        hash ^= 0xFFFF & date.day[1];
      }
    }

    return hash;
  }

  /**
   * This method checks, if the mechanism with the given code is a full encrypt/decrypt mechanism;
   * i.e. it supports the encryptUpdate() and decryptUpdate() functions. This is the information as
   * provided by the table on page 229 of the PKCS#11 v2.11 standard. If this method returns true,
   * the mechanism can be used with the encrypt and decrypt functions including encryptUpdate and
   * decryptUpdate.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a full encrypt/decrypt mechanism. False, otherwise.
   */
  public static boolean isFullEncryptDecryptMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (fullEncryptDecryptMechanisms_ == null) {
      Hashtable fullEncryptDecryptMechanisms = new Hashtable();
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC2_ECB),
          PKCS11Constants.NAME_CKM_RC2_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC2_CBC),
          PKCS11Constants.NAME_CKM_RC2_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC2_CBC_PAD),
          PKCS11Constants.NAME_CKM_RC2_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC4),
          PKCS11Constants.NAME_CKM_RC4);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_ECB),
          PKCS11Constants.NAME_CKM_DES_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_CBC),
          PKCS11Constants.NAME_CKM_DES_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_CBC_PAD),
          PKCS11Constants.NAME_CKM_DES_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES3_ECB),
          PKCS11Constants.NAME_CKM_DES3_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES3_CBC),
          PKCS11Constants.NAME_CKM_DES3_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES3_CBC_PAD),
          PKCS11Constants.NAME_CKM_DES3_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_ECB),
          PKCS11Constants.NAME_CKM_CDMF_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_CBC),
          PKCS11Constants.NAME_CKM_CDMF_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_CBC_PAD),
          PKCS11Constants.NAME_CKM_CDMF_CBC_PAD);

      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_OFB64),
          PKCS11Constants.NAME_CKM_DES_OFB64);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_OFB8),
          PKCS11Constants.NAME_CKM_DES_OFB8);

      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_CFB64),
          PKCS11Constants.NAME_CKM_DES_CFB64);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_DES_CFB8),
          PKCS11Constants.NAME_CKM_DES_CFB8);

      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST_ECB),
          PKCS11Constants.NAME_CKM_CAST_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST_CBC),
          PKCS11Constants.NAME_CKM_CAST_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_ECB),
          PKCS11Constants.NAME_CKM_CAST3_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_CBC),
          PKCS11Constants.NAME_CKM_CAST3_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST3_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_ECB),
          PKCS11Constants.NAME_CKM_CAST5_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_ECB),
          PKCS11Constants.NAME_CKM_CAST128_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_CBC),
          PKCS11Constants.NAME_CKM_CAST5_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_CBC),
          PKCS11Constants.NAME_CKM_CAST128_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST5_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST128_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC5_ECB),
          PKCS11Constants.NAME_CKM_RC5_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC5_CBC),
          PKCS11Constants.NAME_CKM_RC5_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RC5_CBC_PAD),
          PKCS11Constants.NAME_CKM_RC5_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_AES_ECB),
          PKCS11Constants.NAME_CKM_AES_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_AES_CBC),
          PKCS11Constants.NAME_CKM_AES_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_AES_CBC_PAD),
          PKCS11Constants.NAME_CKM_AES_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_BLOWFISH_CBC),
          PKCS11Constants.NAME_CKM_BLOWFISH_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_TWOFISH_CBC),
          PKCS11Constants.NAME_CKM_TWOFISH_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_ECB),
          PKCS11Constants.NAME_CKM_IDEA_ECB);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_CBC),
          PKCS11Constants.NAME_CKM_IDEA_CBC);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_CBC_PAD),
          PKCS11Constants.NAME_CKM_IDEA_CBC_PAD);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_ECB64),
          PKCS11Constants.NAME_CKM_SKIPJACK_ECB64);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_CBC64),
          PKCS11Constants.NAME_CKM_SKIPJACK_CBC64);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_OFB64),
          PKCS11Constants.NAME_CKM_SKIPJACK_OFB64);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB64),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB64);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB32),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB32);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB16),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB16);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_CFB8),
          PKCS11Constants.NAME_CKM_SKIPJACK_CFB8);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_BATON_ECB128),
          PKCS11Constants.NAME_CKM_BATON_ECB128);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_BATON_ECB96),
          PKCS11Constants.NAME_CKM_BATON_ECB96);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_BATON_CBC128),
          PKCS11Constants.NAME_CKM_BATON_CBC128);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_BATON_COUNTER),
          PKCS11Constants.NAME_CKM_BATON_COUNTER);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_BATON_SHUFFLE),
          PKCS11Constants.NAME_CKM_BATON_SHUFFLE);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_JUNIPER_ECB128),
          PKCS11Constants.NAME_CKM_JUNIPER_ECB128);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_JUNIPER_CBC128),
          PKCS11Constants.NAME_CKM_JUNIPER_CBC128);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_JUNIPER_COUNTER),
          PKCS11Constants.NAME_CKM_JUNIPER_COUNTER);
      fullEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_JUNIPER_SHUFFLE),
          PKCS11Constants.NAME_CKM_JUNIPER_SHUFFLE);
      fullEncryptDecryptMechanisms_ = fullEncryptDecryptMechanisms;
    }

    return fullEncryptDecryptMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a single-operation encrypt/decrypt
   * mechanism; i.e. it does not support the encryptUpdate() and decryptUpdate() functions. This is
   * the information as provided by the table on page 229 of the PKCS#11 v2.11 standard. If this
   * method returns true, the mechanism can be used with the encrypt and decrypt functions excluding
   * encryptUpdate and decryptUpdate.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a single-operation encrypt/decrypt mechanism. False,
   *         otherwise.
   */
  public static boolean isSingleOperationEncryptDecryptMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (singleOperationEncryptDecryptMechanisms_ == null) {
      Hashtable singleOperationEncryptDecryptMechanisms = new Hashtable();
      singleOperationEncryptDecryptMechanisms.put(new Long(PKCS11Constants.CKM_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RSA_PKCS);
      singleOperationEncryptDecryptMechanisms.put(new Long(
          PKCS11Constants.CKM_RSA_PKCS_OAEP), PKCS11Constants.NAME_CKM_RSA_PKCS_OAEP);
      singleOperationEncryptDecryptMechanisms.put(
          new Long(PKCS11Constants.CKM_RSA_X_509), PKCS11Constants.NAME_CKM_RSA_X_509);
      singleOperationEncryptDecryptMechanisms_ = singleOperationEncryptDecryptMechanisms;
    }

    return singleOperationEncryptDecryptMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a full sign/verify mechanism; i.e.
   * it supports the signUpdate() and verifyUpdate() functions. This is the information as provided
   * by the table on page 229 of the PKCS#11 v2.11 standard. If this method returns true, the
   * mechanism can be used with the sign and verify functions including signUpdate and verifyUpdate.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a full sign/verify mechanism. False, otherwise.
   */
  public static boolean isFullSignVerifyMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (fullSignVerifyMechanisms_ == null) {
      Hashtable fullSignVerifyMechanisms = new Hashtable();
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_MD2_RSA_PKCS),
          PKCS11Constants.NAME_CKM_MD2_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_MD5_RSA_PKCS),
          PKCS11Constants.NAME_CKM_MD5_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA1_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA1_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD128_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RIPEMD128_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD160_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RIPEMD160_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA1_RSA_PKCS_PSS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA1_RSA_X9_31),
          PKCS11Constants.NAME_CKM_SHA1_RSA_X9_31);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_DSA_SHA1),
          PKCS11Constants.NAME_CKM_DSA_SHA1);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA256_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA256_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA384_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA384_RSA_PKCS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA512_RSA_PKCS),
          PKCS11Constants.NAME_CKM_SHA512_RSA_PKCS);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA256_RSA_PKCS_PSS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA384_RSA_PKCS_PSS);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_SHA512_RSA_PKCS_PSS);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RC2_MAC),
          PKCS11Constants.NAME_CKM_RC2_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RC2_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_RC2_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_DES_MAC),
          PKCS11Constants.NAME_CKM_DES_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_DES_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_DES_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_DES3_MAC),
          PKCS11Constants.NAME_CKM_DES3_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_DES3_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_DES3_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_MAC),
          PKCS11Constants.NAME_CKM_CDMF_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CDMF_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_MD2_HMAC),
          PKCS11Constants.NAME_CKM_MD2_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_MD2_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_MD2_HMAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_MD5_HMAC),
          PKCS11Constants.NAME_CKM_MD5_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_MD5_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_MD5_HMAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA_1_HMAC),
          PKCS11Constants.NAME_CKM_SHA_1_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA_1_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA_1_HMAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD128_HMAC),
          PKCS11Constants.NAME_CKM_RIPEMD128_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD128_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_RIPEMD128_HMAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD160_HMAC),
          PKCS11Constants.NAME_CKM_RIPEMD160_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD160_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_RIPEMD160_HMAC_GENERAL);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA256_HMAC),
          PKCS11Constants.NAME_CKM_SHA256_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA256_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA256_HMAC_GENERAL);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA384_HMAC),
          PKCS11Constants.NAME_CKM_SHA384_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA384_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA384_HMAC_GENERAL);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA512_HMAC),
          PKCS11Constants.NAME_CKM_SHA512_HMAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SHA512_HMAC_GENERAL),
          PKCS11Constants.NAME_CKM_SHA512_HMAC_GENERAL);

      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST_MAC),
          PKCS11Constants.NAME_CKM_CAST_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_MAC),
          PKCS11Constants.NAME_CKM_CAST3_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST3_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_MAC),
          PKCS11Constants.NAME_CKM_CAST5_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_MAC),
          PKCS11Constants.NAME_CKM_CAST128_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST5_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_CAST128_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RC5_MAC),
          PKCS11Constants.NAME_CKM_RC5_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RC5_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_RC5_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_AES_MAC),
          PKCS11Constants.NAME_CKM_AES_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_AES_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_AES_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_MAC),
          PKCS11Constants.NAME_CKM_IDEA_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_MAC_GENERAL),
          PKCS11Constants.NAME_CKM_IDEA_MAC_GENERAL);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SSL3_MD5_MAC),
          PKCS11Constants.NAME_CKM_SSL3_MD5_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_SSL3_SHA1_MAC),
          PKCS11Constants.NAME_CKM_SSL3_SHA1_MAC);
      fullSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_ECDSA_SHA1),
          PKCS11Constants.NAME_CKM_ECDSA_SHA1);
      fullSignVerifyMechanisms_ = fullSignVerifyMechanisms;
    }

    return fullSignVerifyMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a single-operation sign/verify
   * mechanism; i.e. it does not support the signUpdate() and encryptUpdate() functions. This is the
   * information as provided by the table on page 229 of the PKCS#11 v2.11 standard. If this method
   * returns true, the mechanism can be used with the sign and verify functions excluding signUpdate
   * and encryptUpdate.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a single-operation sign/verify mechanism. False,
   *         otherwise.
   */
  public static boolean isSingleOperationSignVerifyMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (singleOperationSignVerifyMechanisms_ == null) {
      Hashtable singleOperationSignVerifyMechanisms = new Hashtable();
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RSA_PKCS);
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RSA_PKCS_PSS),
          PKCS11Constants.NAME_CKM_RSA_PKCS_PSS);
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RSA_9796),
          PKCS11Constants.NAME_CKM_RSA_9796);
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RSA_X_509),
          PKCS11Constants.NAME_CKM_RSA_X_509);
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_RSA_X9_31),
          PKCS11Constants.NAME_CKM_RSA_X9_31);
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_DSA),
          PKCS11Constants.NAME_CKM_DSA);
      singleOperationSignVerifyMechanisms.put(new Long(
          PKCS11Constants.CKM_FORTEZZA_TIMESTAMP),
          PKCS11Constants.NAME_CKM_FORTEZZA_TIMESTAMP);
      singleOperationSignVerifyMechanisms.put(new Long(PKCS11Constants.CKM_ECDSA),
          PKCS11Constants.NAME_CKM_ECDSA);
      singleOperationSignVerifyMechanisms_ = singleOperationSignVerifyMechanisms;
    }

    return singleOperationSignVerifyMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a sign/verify mechanism with
   * message recovery. This is the information as provided by the table on page 229 of the PKCS#11
   * v2.11 standard. If this method returns true, the mechanism can be used with the signRecover and
   * verifyRecover functions.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a sign/verify mechanism with message recovery.
   *         False, otherwise.
   */
  public static boolean isSignVerifyRecoverMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (signVerifyRecoverMechanisms_ == null) {
      Hashtable signVerifyRecoverMechanisms = new Hashtable();
      signVerifyRecoverMechanisms.put(new Long(PKCS11Constants.CKM_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RSA_PKCS);
      signVerifyRecoverMechanisms.put(new Long(PKCS11Constants.CKM_RSA_9796),
          PKCS11Constants.NAME_CKM_RSA_9796);
      signVerifyRecoverMechanisms.put(new Long(PKCS11Constants.CKM_RSA_X_509),
          PKCS11Constants.NAME_CKM_RSA_X_509);
      signVerifyRecoverMechanisms_ = signVerifyRecoverMechanisms;
    }

    return signVerifyRecoverMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a digest mechanism. This is the
   * information as provided by the table on page 229 of the PKCS#11 v2.11 standard. If this method
   * returns true, the mechanism can be used with the digest functions.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a digest mechanism. False, otherwise.
   */
  public static boolean isDigestMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (digestMechanisms_ == null) {
      Hashtable digestMechanisms = new Hashtable();
      digestMechanisms.put(new Long(PKCS11Constants.CKM_MD2),
          PKCS11Constants.NAME_CKM_MD2);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_MD5),
          PKCS11Constants.NAME_CKM_MD5);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_SHA_1),
          PKCS11Constants.NAME_CKM_SHA_1);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD128),
          PKCS11Constants.NAME_CKM_RIPEMD128);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_RIPEMD160),
          PKCS11Constants.NAME_CKM_RIPEMD160);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_SHA256),
          PKCS11Constants.NAME_CKM_SHA256);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_SHA384),
          PKCS11Constants.NAME_CKM_SHA384);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_SHA512),
          PKCS11Constants.NAME_CKM_SHA512);
      digestMechanisms.put(new Long(PKCS11Constants.CKM_FASTHASH),
          PKCS11Constants.NAME_CKM_FASTHASH);
      digestMechanisms_ = digestMechanisms;
    }

    return digestMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a key generation mechanism for
   * generating symmetric keys. This is the information as provided by the table on page 229 of the
   * PKCS#11 v2.11 standard. If this method returns true, the mechanism can be used with the
   * generateKey function.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a key generation mechanism. False, otherwise.
   */
  public static boolean isKeyGenerationMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (keyGenerationMechanisms_ == null) {
      Hashtable keyGenerationMechanisms = new Hashtable();
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DSA_PARAMETER_GEN),
          PKCS11Constants.NAME_CKM_DSA_PARAMETER_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DH_PKCS_PARAMETER_GEN),
          PKCS11Constants.NAME_CKM_DH_PKCS_PARAMETER_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_X9_42_DH_PARAMETER_GEN),
          PKCS11Constants.NAME_CKM_X9_42_DH_PARAMETER_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_RC2_KEY_GEN),
          PKCS11Constants.NAME_CKM_RC2_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_RC4_KEY_GEN),
          PKCS11Constants.NAME_CKM_RC4_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DES_KEY_GEN),
          PKCS11Constants.NAME_CKM_DES_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DES2_KEY_GEN),
          PKCS11Constants.NAME_CKM_DES2_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DES3_KEY_GEN),
          PKCS11Constants.NAME_CKM_DES3_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_KEY_GEN),
          PKCS11Constants.NAME_CKM_CDMF_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_CAST_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST3_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST5_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_KEY_GEN),
          PKCS11Constants.NAME_CKM_CAST128_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_RC5_KEY_GEN),
          PKCS11Constants.NAME_CKM_RC5_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_AES_KEY_GEN),
          PKCS11Constants.NAME_CKM_AES_KEY_GEN);

      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_BLOWFISH_KEY_GEN),
          PKCS11Constants.NAME_CKM_BLOWFISH_KEY_GEN);

      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_TWOFISH_KEY_GEN),
          PKCS11Constants.NAME_CKM_TWOFISH_KEY_GEN);

      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_KEY_GEN),
          PKCS11Constants.NAME_CKM_IDEA_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN),
          PKCS11Constants.NAME_CKM_GENERIC_SECRET_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_SSL3_PRE_MASTER_KEY_GEN),
          PKCS11Constants.NAME_CKM_SSL3_PRE_MASTER_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_TLS_PRE_MASTER_KEY_GEN),
          PKCS11Constants.NAME_CKM_TLS_PRE_MASTER_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_MD2_DES_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD2_DES_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_MD5_DES_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_DES_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST3_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST3_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST5_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST5_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_MD5_CAST128_CBC),
          PKCS11Constants.NAME_CKM_PBE_MD5_CAST128_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_CAST5_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_CAST5_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_CAST128_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_CAST128_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC4_128),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC4_128);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC4_40),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC4_40);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_DES3_EDE_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_DES3_EDE_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_DES2_EDE_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_DES2_EDE_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC2_128_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC2_128_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBE_SHA1_RC2_40_CBC),
          PKCS11Constants.NAME_CKM_PBE_SHA1_RC2_40_CBC);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PKCS5_PBKD2),
          PKCS11Constants.NAME_CKM_PKCS5_PBKD2);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_PBA_SHA1_WITH_SHA1_HMAC),
          PKCS11Constants.NAME_CKM_PBA_SHA1_WITH_SHA1_HMAC);

      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_WTLS_PRE_MASTER_KEY_GEN),
          PKCS11Constants.NAME_CKM_WTLS_PRE_MASTER_KEY_GEN);

      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_KEY_GEN),
          PKCS11Constants.NAME_CKM_SKIPJACK_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_BATON_KEY_GEN),
          PKCS11Constants.NAME_CKM_BATON_KEY_GEN);
      keyGenerationMechanisms.put(new Long(PKCS11Constants.CKM_JUNIPER_KEY_GEN),
          PKCS11Constants.NAME_CKM_JUNIPER_KEY_GEN);
      keyGenerationMechanisms_ = keyGenerationMechanisms;
    }

    return keyGenerationMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a key-pair generation mechanism for
   * generating key-pairs. This is the information as provided by the table on page 229 of the
   * PKCS#11 v2.11 standard. If this method returns true, the mechanism can be used with the
   * generateKeyPair function.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a key-pair generation mechanism. False, otherwise.
   */
  public static boolean isKeyPairGenerationMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (keyPairGenerationMechanisms_ == null) {
      Hashtable keyPairGenerationMechanisms = new Hashtable();
      keyPairGenerationMechanisms.put(
          new Long(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_RSA_PKCS_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(
          new Long(PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_RSA_X9_31_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_DSA_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DH_PKCS_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_DH_PKCS_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(new Long(PKCS11Constants.CKM_KEA_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_KEA_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(new Long(PKCS11Constants.CKM_ECDSA_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_ECDSA_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(new Long(PKCS11Constants.CKM_EC_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_EC_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(new Long(PKCS11Constants.CKM_DH_PKCS_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_DH_PKCS_KEY_PAIR_GEN);
      keyPairGenerationMechanisms.put(
          new Long(PKCS11Constants.CKM_X9_42_DH_KEY_PAIR_GEN),
          PKCS11Constants.NAME_CKM_X9_42_DH_KEY_PAIR_GEN);
      keyPairGenerationMechanisms_ = keyPairGenerationMechanisms;
    }

    return keyPairGenerationMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a wrap/unwrap mechanism; i.e. it
   * supports the wrapKey() and unwrapKey() functions. This is the information as provided by the
   * table on page 229 of the PKCS#11 v2.11 standard. If this method returns true, the mechanism can
   * be used with the wrapKey and unwrapKey functions.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a wrap/unwrap mechanism. False, otherwise.
   */
  public static boolean isWrapUnwrapMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (wrapUnwrapMechanisms_ == null) {
      Hashtable wrapUnwrapMechanisms = new Hashtable();
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RSA_PKCS),
          PKCS11Constants.NAME_CKM_RSA_PKCS);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RSA_X_509),
          PKCS11Constants.NAME_CKM_RSA_X_509);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RSA_PKCS_OAEP),
          PKCS11Constants.NAME_CKM_RSA_PKCS_OAEP);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RC2_ECB),
          PKCS11Constants.NAME_CKM_RC2_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RC2_CBC),
          PKCS11Constants.NAME_CKM_RC2_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RC2_CBC_PAD),
          PKCS11Constants.NAME_CKM_RC2_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_DES_ECB),
          PKCS11Constants.NAME_CKM_DES_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_DES_CBC),
          PKCS11Constants.NAME_CKM_DES_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_DES_CBC_PAD),
          PKCS11Constants.NAME_CKM_DES_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_DES3_ECB),
          PKCS11Constants.NAME_CKM_DES3_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_DES3_CBC),
          PKCS11Constants.NAME_CKM_DES3_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_DES3_CBC_PAD),
          PKCS11Constants.NAME_CKM_DES3_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_ECB),
          PKCS11Constants.NAME_CKM_CDMF_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_CBC),
          PKCS11Constants.NAME_CKM_CDMF_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CDMF_CBC_PAD),
          PKCS11Constants.NAME_CKM_CDMF_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST_ECB),
          PKCS11Constants.NAME_CKM_CAST_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST_CBC),
          PKCS11Constants.NAME_CKM_CAST_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_ECB),
          PKCS11Constants.NAME_CKM_CAST3_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_CBC),
          PKCS11Constants.NAME_CKM_CAST3_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST3_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST3_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_ECB),
          PKCS11Constants.NAME_CKM_CAST5_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_ECB),
          PKCS11Constants.NAME_CKM_CAST128_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_CBC),
          PKCS11Constants.NAME_CKM_CAST5_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_CBC),
          PKCS11Constants.NAME_CKM_CAST128_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST5_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST5_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_CAST128_CBC_PAD),
          PKCS11Constants.NAME_CKM_CAST128_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RC5_ECB),
          PKCS11Constants.NAME_CKM_RC5_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RC5_CBC),
          PKCS11Constants.NAME_CKM_RC5_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_RC5_CBC_PAD),
          PKCS11Constants.NAME_CKM_RC5_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_ECB),
          PKCS11Constants.NAME_CKM_IDEA_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_CBC),
          PKCS11Constants.NAME_CKM_IDEA_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_IDEA_CBC_PAD),
          PKCS11Constants.NAME_CKM_IDEA_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_KEY_WRAP_LYNKS),
          PKCS11Constants.NAME_CKM_KEY_WRAP_LYNKS);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_KEY_WRAP_SET_OAEP),
          PKCS11Constants.NAME_CKM_KEY_WRAP_SET_OAEP);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_WRAP),
          PKCS11Constants.NAME_CKM_SKIPJACK_WRAP);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_PRIVATE_WRAP),
          PKCS11Constants.NAME_CKM_SKIPJACK_PRIVATE_WRAP);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_SKIPJACK_RELAYX),
          PKCS11Constants.NAME_CKM_SKIPJACK_RELAYX);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_BATON_WRAP),
          PKCS11Constants.NAME_CKM_BATON_WRAP);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_JUNIPER_WRAP),
          PKCS11Constants.NAME_CKM_JUNIPER_WRAP);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_AES_ECB),
          PKCS11Constants.NAME_CKM_AES_ECB);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_AES_CBC),
          PKCS11Constants.NAME_CKM_AES_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_AES_CBC_PAD),
          PKCS11Constants.NAME_CKM_AES_CBC_PAD);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_BLOWFISH_CBC),
          PKCS11Constants.NAME_CKM_BLOWFISH_CBC);
      wrapUnwrapMechanisms.put(new Long(PKCS11Constants.CKM_TWOFISH_CBC),
          PKCS11Constants.NAME_CKM_TWOFISH_CBC);
      wrapUnwrapMechanisms_ = wrapUnwrapMechanisms;
    }

    return wrapUnwrapMechanisms_.containsKey(new Long(mechanismCode));
  }

  /**
   * This method checks, if the mechanism with the given code is a key derivation mechanism. This is
   * the information as provided by the table on page 229 of the PKCS#11 v2.11 standard. If this
   * method returns true, the mechanism can be used with the deriveKey function.
   * 
   * @param mechanismCode
   *          The code of the mechanism to check.
   * @return True, if the provided mechanism is a key derivation mechanism. False, otherwise.
   */
  public static boolean isKeyDerivationMechanism(long mechanismCode) {
    // build the hashtable on demand (=first use)
    if (keyDerivationMechanisms_ == null) {
      Hashtable keyDerivationMechanisms = new Hashtable();
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_DH_PKCS_DERIVE),
          PKCS11Constants.NAME_CKM_DH_PKCS_DERIVE);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY),
          PKCS11Constants.NAME_CKM_CONCATENATE_BASE_AND_KEY);
      keyDerivationMechanisms.put(
          new Long(PKCS11Constants.CKM_CONCATENATE_BASE_AND_DATA),
          PKCS11Constants.NAME_CKM_CONCATENATE_BASE_AND_DATA);
      keyDerivationMechanisms.put(
          new Long(PKCS11Constants.CKM_CONCATENATE_DATA_AND_BASE),
          PKCS11Constants.NAME_CKM_CONCATENATE_DATA_AND_BASE);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_XOR_BASE_AND_DATA),
          PKCS11Constants.NAME_CKM_XOR_BASE_AND_DATA);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY),
          PKCS11Constants.NAME_CKM_EXTRACT_KEY_FROM_KEY);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_SSL3_MASTER_KEY_DERIVE);
      keyDerivationMechanisms.put(
          new Long(PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE_DH),
          PKCS11Constants.NAME_CKM_SSL3_MASTER_KEY_DERIVE_DH);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_SSL3_KEY_AND_MAC_DERIVE);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_TLS_MASTER_KEY_DERIVE);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE_DH),
          PKCS11Constants.NAME_CKM_TLS_MASTER_KEY_DERIVE_DH);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_TLS_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_TLS_KEY_AND_MAC_DERIVE);

      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_TLS_PRF),
          PKCS11Constants.NAME_CKM_TLS_PRF);

      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_MD5_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_MD5_KEY_DERIVATION);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_MD2_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_MD2_KEY_DERIVATION);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_SHA1_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA1_KEY_DERIVATION);

      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_SHA256_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA256_KEY_DERIVATION);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_SHA384_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA384_KEY_DERIVATION);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_SHA512_KEY_DERIVATION),
          PKCS11Constants.NAME_CKM_SHA512_KEY_DERIVATION);

      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_TLS_MASTER_KEY_DERIVE);
      keyDerivationMechanisms.put(new Long(
          PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC),
          PKCS11Constants.NAME_CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC);
      keyDerivationMechanisms.put(new Long(
          PKCS11Constants.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE);
      keyDerivationMechanisms.put(new Long(
          PKCS11Constants.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE),
          PKCS11Constants.NAME_CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_WTLS_PRF),
          PKCS11Constants.NAME_CKM_WTLS_PRF);

      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_KEA_KEY_DERIVE),
          PKCS11Constants.NAME_CKM_KEA_KEY_DERIVE);

      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES_ECB_ENCRYPT_DATA);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES_CBC_ENCRYPT_DATA);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES3_ECB_ENCRYPT_DATA);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_DES3_CBC_ENCRYPT_DATA);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_AES_ECB_ENCRYPT_DATA);
      keyDerivationMechanisms.put(new Long(PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA),
          PKCS11Constants.NAME_CKM_AES_CBC_ENCRYPT_DATA);

      keyDerivationMechanisms_ = keyDerivationMechanisms;
    }

    return keyDerivationMechanisms_.containsKey(new Long(mechanismCode));
  }

}
