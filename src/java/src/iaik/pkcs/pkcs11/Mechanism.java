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

import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent a mechansim as defined in PKCS#11. There are constants defined
 * for all mechanisms that PKCS#11 version 2.11 defines.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class Mechanism implements Cloneable {

  /*
   * For each predefined mechanism of PKCS#11 v2.11 there is a constant. Refer to the standard fro
   * details.
   */
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism RSA_PKCS_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_PKCS)</code>
   */
  public static final Mechanism RSA_PKCS = new Mechanism(PKCS11Constants.CKM_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_9796)</code>
   */
  public static final Mechanism RSA_9796 = new Mechanism(PKCS11Constants.CKM_RSA_9796);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_X_509)</code>
   */
  public static final Mechanism RSA_X_509 = new Mechanism(PKCS11Constants.CKM_RSA_X_509);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD2_RSA_PKCS)</code>
   */
  public static final Mechanism MD2_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_MD2_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD5_RSA_PKCS)</code>
   */
  public static final Mechanism MD5_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_MD5_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA1_RSA_PKCS)</code>
   */
  public static final Mechanism SHA1_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_SHA1_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD128_RSA_PKCS)</code>
   */
  public static final Mechanism RIPEMD128_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_RIPEMD128_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD160_RSA_PKCS)</code>
   */
  public static final Mechanism RIPEMD160_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_RIPEMD160_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA256_RSA_PKCS)</code>
   */
  public static final Mechanism SHA256_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_SHA256_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA384_RSA_PKCS)</code>
   */
  public static final Mechanism SHA384_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_SHA384_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA512_RSA_PKCS)</code>
   */
  public static final Mechanism SHA512_RSA_PKCS = new Mechanism(
      PKCS11Constants.CKM_SHA512_RSA_PKCS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_OAEP)</code>
   */
  public static final Mechanism RSA_PKCS_OAEP = new Mechanism(
      PKCS11Constants.CKM_RSA_PKCS_OAEP);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism RSA_X9_31_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_RSA_X9_31_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_X9_31)</code>
   */
  public static final Mechanism RSA_X9_31 = new Mechanism(PKCS11Constants.CKM_RSA_X9_31);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA1_RSA_X9_31)</code>
   */
  public static final Mechanism SHA1_RSA_X9_31 = new Mechanism(
      PKCS11Constants.CKM_SHA1_RSA_X9_31);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_PSS)</code>
   */
  public static final Mechanism RSA_PKCS_PSS = new Mechanism(
      PKCS11Constants.CKM_RSA_PKCS_PSS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS)</code>
   */
  public static final Mechanism SHA1_RSA_PKCS_PSS = new Mechanism(
      PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS)</code>
   */
  public static final Mechanism SHA256_RSA_PKCS_PSS = new Mechanism(
      PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS)</code>
   */
  public static final Mechanism SHA384_RSA_PKCS_PSS = new Mechanism(
      PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS)</code>
   */
  public static final Mechanism SHA512_RSA_PKCS_PSS = new Mechanism(
      PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism DSA_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_DSA_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DSA)</code>
   */
  public static final Mechanism DSA = new Mechanism(PKCS11Constants.CKM_DSA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DSA_SHA1)</code>
   */
  public static final Mechanism DSA_SHA1 = new Mechanism(PKCS11Constants.CKM_DSA_SHA1);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DH_PKCS_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism DH_PKCS_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_DH_PKCS_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DH_PKCS_DERIVE)</code>
   */
  public static final Mechanism DH_PKCS_DERIVE = new Mechanism(
      PKCS11Constants.CKM_DH_PKCS_DERIVE);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_X9_42_DH_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism X9_42_DH_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_X9_42_DH_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_X9_42_DH_DERIVE)</code>
   */
  public static final Mechanism X9_42_DH_DERIVE = new Mechanism(
      PKCS11Constants.CKM_X9_42_DH_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_X9_42_DH_HYBRID_DERIVE)</code>
   */
  public static final Mechanism X9_42_DH_HYBRID_DERIVE = new Mechanism(
      PKCS11Constants.CKM_X9_42_DH_HYBRID_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_X9_42_MQV_DERIVE)</code>
   */
  public static final Mechanism X9_42_MQV_DERIVE = new Mechanism(
      PKCS11Constants.CKM_X9_42_MQV_DERIVE);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC2_KEY_GEN)</code>
   */
  public static final Mechanism RC2_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_RC2_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC2_ECB)</code>
   */
  public static final Mechanism RC2_ECB = new Mechanism(PKCS11Constants.CKM_RC2_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC2_CBC)</code>
   */
  public static final Mechanism RC2_CBC = new Mechanism(PKCS11Constants.CKM_RC2_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC2_MAC)</code>
   */
  public static final Mechanism RC2_MAC = new Mechanism(PKCS11Constants.CKM_RC2_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC2_MAC_GENERAL)</code>
   */
  public static final Mechanism RC2_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_RC2_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC2_CBC_PAD)</code>
   */
  public static final Mechanism RC2_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_RC2_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC4_KEY_GEN)</code>
   */
  public static final Mechanism RC4_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_RC4_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC4)</code>
   */
  public static final Mechanism RC4 = new Mechanism(PKCS11Constants.CKM_RC4);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_KEY_GEN)</code>
   */
  public static final Mechanism DES_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_DES_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_ECB)</code>
   */
  public static final Mechanism DES_ECB = new Mechanism(PKCS11Constants.CKM_DES_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_CBC)</code>
   */
  public static final Mechanism DES_CBC = new Mechanism(PKCS11Constants.CKM_DES_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_MAC)</code>
   */
  public static final Mechanism DES_MAC = new Mechanism(PKCS11Constants.CKM_DES_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_MAC_GENERAL)</code>
   */
  public static final Mechanism DES_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_DES_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_CBC_PAD)</code>
   */
  public static final Mechanism DES_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_DES_CBC_PAD);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_OFB64)</code>
   */
  public static final Mechanism DES_OFB64 = new Mechanism(PKCS11Constants.CKM_DES_OFB64);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_OFB8)</code>
   */
  public static final Mechanism DES_OFB8 = new Mechanism(PKCS11Constants.CKM_DES_OFB8);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_CFB64)</code>
   */
  public static final Mechanism DES_CFB64 = new Mechanism(PKCS11Constants.CKM_DES_CFB64);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_CFB8)</code>
   */
  public static final Mechanism DES_CFB8 = new Mechanism(PKCS11Constants.CKM_DES_CFB8);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES2_KEY_GEN)</code>
   */
  public static final Mechanism DES2_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_DES2_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_KEY_GEN)</code>
   */
  public static final Mechanism DES3_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_DES3_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_ECB)</code>
   */
  public static final Mechanism DES3_ECB = new Mechanism(PKCS11Constants.CKM_DES3_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_CBC)</code>
   */
  public static final Mechanism DES3_CBC = new Mechanism(PKCS11Constants.CKM_DES3_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_MAC)</code>
   */
  public static final Mechanism DES3_MAC = new Mechanism(PKCS11Constants.CKM_DES3_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_MAC_GENERAL)</code>
   */
  public static final Mechanism DES3_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_DES3_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_CBC_PAD)</code>
   */
  public static final Mechanism DES3_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_DES3_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CDMF_KEY_GEN)</code>
   */
  public static final Mechanism CDMF_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_CDMF_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CDMF_ECB)</code>
   */
  public static final Mechanism CDMF_ECB = new Mechanism(PKCS11Constants.CKM_CDMF_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CDMF_CBC)</code>
   */
  public static final Mechanism CDMF_CBC = new Mechanism(PKCS11Constants.CKM_CDMF_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CDMF_MAC)</code>
   */
  public static final Mechanism CDMF_MAC = new Mechanism(PKCS11Constants.CKM_CDMF_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CDMF_MAC_GENERAL)</code>
   */
  public static final Mechanism CDMF_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_CDMF_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CDMF_CBC_PAD)</code>
   */
  public static final Mechanism CDMF_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_CDMF_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD2)</code>
   */
  public static final Mechanism MD2 = new Mechanism(PKCS11Constants.CKM_MD2);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD2_HMAC)</code>
   */
  public static final Mechanism MD2_HMAC = new Mechanism(PKCS11Constants.CKM_MD2_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD2_HMAC_GENERAL)</code>
   */
  public static final Mechanism MD2_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_MD2_HMAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD5)</code>
   */
  public static final Mechanism MD5 = new Mechanism(PKCS11Constants.CKM_MD5);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD5_HMAC)</code>
   */
  public static final Mechanism MD5_HMAC = new Mechanism(PKCS11Constants.CKM_MD5_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD5_HMAC_GENERAL)</code>
   */
  public static final Mechanism MD5_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_MD5_HMAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA_1)</code>
   */
  public static final Mechanism SHA_1 = new Mechanism(PKCS11Constants.CKM_SHA_1);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA_1_HMAC)</code>
   */
  public static final Mechanism SHA_1_HMAC = new Mechanism(PKCS11Constants.CKM_SHA_1_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA_1_HMAC_GENERAL)</code>
   */
  public static final Mechanism SHA_1_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_SHA_1_HMAC_GENERAL);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA256)</code>
   */
  public static final Mechanism SHA256 = new Mechanism(PKCS11Constants.CKM_SHA256);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA256_HMAC)</code>
   */
  public static final Mechanism SHA256_HMAC = new Mechanism(
      PKCS11Constants.CKM_SHA256_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA256_HMAC_GENERAL)</code>
   */
  public static final Mechanism SHA256_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_SHA256_HMAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA384)</code>
   */
  public static final Mechanism SHA384 = new Mechanism(PKCS11Constants.CKM_SHA384);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA384_HMAC)</code>
   */
  public static final Mechanism SHA384_HMAC = new Mechanism(
      PKCS11Constants.CKM_SHA384_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA384_HMAC_GENERAL)</code>
   */
  public static final Mechanism SHA384_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_SHA384_HMAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA512)</code>
   */
  public static final Mechanism SHA512 = new Mechanism(PKCS11Constants.CKM_SHA512);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA512_HMAC)</code>
   */
  public static final Mechanism SHA512_HMAC = new Mechanism(
      PKCS11Constants.CKM_SHA512_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA512_HMAC_GENERAL)</code>
   */
  public static final Mechanism SHA512_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_SHA512_HMAC_GENERAL);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD128)</code>
   */
  public static final Mechanism RIPEMD128 = new Mechanism(PKCS11Constants.CKM_RIPEMD128);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD128_HMAC)</code>
   */
  public static final Mechanism RIPEMD128_HMAC = new Mechanism(
      PKCS11Constants.CKM_RIPEMD128_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD128_HMAC_GENERAL)</code>
   */
  public static final Mechanism RIPEMD128_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_RIPEMD128_HMAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD160)</code>
   */
  public static final Mechanism RIPEMD160 = new Mechanism(PKCS11Constants.CKM_RIPEMD160);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD160_HMAC)</code>
   */
  public static final Mechanism RIPEMD160_HMAC = new Mechanism(
      PKCS11Constants.CKM_RIPEMD160_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RIPEMD160_HMAC_GENERAL)</code>
   */
  public static final Mechanism RIPEMD160_HMAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_RIPEMD160_HMAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST_KEY_GEN)</code>
   */
  public static final Mechanism CAST_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_CAST_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST_ECB)</code>
   */
  public static final Mechanism CAST_ECB = new Mechanism(PKCS11Constants.CKM_CAST_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST_CBC)</code>
   */
  public static final Mechanism CAST_CBC = new Mechanism(PKCS11Constants.CKM_CAST_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST_MAC)</code>
   */
  public static final Mechanism CAST_MAC = new Mechanism(PKCS11Constants.CKM_CAST_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST_MAC_GENERAL)</code>
   */
  public static final Mechanism CAST_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_CAST_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST_CBC_PAD)</code>
   */
  public static final Mechanism CAST_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_CAST_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST3_KEY_GEN)</code>
   */
  public static final Mechanism CAST3_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_CAST3_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST3_ECB)</code>
   */
  public static final Mechanism CAST3_ECB = new Mechanism(PKCS11Constants.CKM_CAST3_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST3_CBC)</code>
   */
  public static final Mechanism CAST3_CBC = new Mechanism(PKCS11Constants.CKM_CAST3_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST3_MAC)</code>
   */
  public static final Mechanism CAST3_MAC = new Mechanism(PKCS11Constants.CKM_CAST3_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST3_MAC_GENERAL)</code>
   */
  public static final Mechanism CAST3_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_CAST3_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST3_CBC_PAD)</code>
   */
  public static final Mechanism CAST3_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_CAST3_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST5_KEY_GEN)</code>
   */
  public static final Mechanism CAST5_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_CAST5_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST128_KEY_GEN)</code>
   */
  public static final Mechanism CAST128_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_CAST128_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST5_ECB)</code>
   */
  public static final Mechanism CAST5_ECB = new Mechanism(PKCS11Constants.CKM_CAST5_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST128_ECB)</code>
   */
  public static final Mechanism CAST128_ECB = new Mechanism(
      PKCS11Constants.CKM_CAST128_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST5_CBC)</code>
   */
  public static final Mechanism CAST5_CBC = new Mechanism(PKCS11Constants.CKM_CAST5_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST128_CBC)</code>
   */
  public static final Mechanism CAST128_CBC = new Mechanism(
      PKCS11Constants.CKM_CAST128_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST5_MAC)</code>
   */
  public static final Mechanism CAST5_MAC = new Mechanism(PKCS11Constants.CKM_CAST5_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST128_MAC)</code>
   */
  public static final Mechanism CAST128_MAC = new Mechanism(
      PKCS11Constants.CKM_CAST128_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST5_MAC_GENERAL)</code>
   */
  public static final Mechanism CAST5_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_CAST5_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST128_MAC_GENERAL)</code>
   */
  public static final Mechanism CAST128_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_CAST128_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST5_CBC_PAD)</code>
   */
  public static final Mechanism CAST5_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_CAST5_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CAST128_CBC_PAD)</code>
   */
  public static final Mechanism CAST128_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_CAST128_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC5_KEY_GEN)</code>
   */
  public static final Mechanism RC5_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_RC5_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC5_ECB)</code>
   */
  public static final Mechanism RC5_ECB = new Mechanism(PKCS11Constants.CKM_RC5_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC5_CBC)</code>
   */
  public static final Mechanism RC5_CBC = new Mechanism(PKCS11Constants.CKM_RC5_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC5_MAC)</code>
   */
  public static final Mechanism RC5_MAC = new Mechanism(PKCS11Constants.CKM_RC5_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC5_MAC_GENERAL)</code>
   */
  public static final Mechanism RC5_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_RC5_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_RC5_CBC_PAD)</code>
   */
  public static final Mechanism RC5_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_RC5_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_IDEA_KEY_GEN)</code>
   */
  public static final Mechanism IDEA_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_IDEA_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_IDEA_ECB)</code>
   */
  public static final Mechanism IDEA_ECB = new Mechanism(PKCS11Constants.CKM_IDEA_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_IDEA_CBC)</code>
   */
  public static final Mechanism IDEA_CBC = new Mechanism(PKCS11Constants.CKM_IDEA_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_IDEA_MAC)</code>
   */
  public static final Mechanism IDEA_MAC = new Mechanism(PKCS11Constants.CKM_IDEA_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_IDEA_MAC_GENERAL)</code>
   */
  public static final Mechanism IDEA_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_IDEA_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_IDEA_CBC_PAD)</code>
   */
  public static final Mechanism IDEA_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_IDEA_CBC_PAD);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN)</code>
   */
  public static final Mechanism GENERIC_SECRET_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY)</code>
   */
  public static final Mechanism CONCATENATE_BASE_AND_KEY = new Mechanism(
      PKCS11Constants.CKM_CONCATENATE_BASE_AND_KEY);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CONCATENATE_BASE_AND_DATA)</code>
   */
  public static final Mechanism CONCATENATE_BASE_AND_DATA = new Mechanism(
      PKCS11Constants.CKM_CONCATENATE_BASE_AND_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_CONCATENATE_DATA_AND_BASE)</code>
   */
  public static final Mechanism CONCATENATE_DATA_AND_BASE = new Mechanism(
      PKCS11Constants.CKM_CONCATENATE_DATA_AND_BASE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_XOR_BASE_AND_DATA)</code>
   */
  public static final Mechanism XOR_BASE_AND_DATA = new Mechanism(
      PKCS11Constants.CKM_XOR_BASE_AND_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY)</code>
   */
  public static final Mechanism EXTRACT_KEY_FROM_KEY = new Mechanism(
      PKCS11Constants.CKM_EXTRACT_KEY_FROM_KEY);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SSL3_PRE_MASTER_KEY_GEN)</code>
   */
  public static final Mechanism SSL3_PRE_MASTER_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_SSL3_PRE_MASTER_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE)</code>
   */
  public static final Mechanism SSL3_MASTER_KEY_DERIVE = new Mechanism(
      PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE)</code>
   */
  public static final Mechanism SSL3_KEY_AND_MAC_DERIVE = new Mechanism(
      PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE_DH)</code>
   */
  public static final Mechanism SSL3_MASTER_KEY_DERIVE_DH = new Mechanism(
      PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE_DH);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_TLS_PRE_MASTER_KEY_GEN)</code>
   */
  public static final Mechanism TLS_PRE_MASTER_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_TLS_PRE_MASTER_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE)</code>
   */
  public static final Mechanism TLS_MASTER_KEY_DERIVE = new Mechanism(
      PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_TLS_KEY_AND_MAC_DERIVE)</code>
   */
  public static final Mechanism TLS_KEY_AND_MAC_DERIVE = new Mechanism(
      PKCS11Constants.CKM_TLS_KEY_AND_MAC_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE_DH)</code>
   */
  public static final Mechanism TLS_MASTER_KEY_DERIVE_DH = new Mechanism(
      PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE_DH);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_TLS_PRF)</code>
   */
  public static final Mechanism TLS_PRF = new Mechanism(PKCS11Constants.CKM_TLS_PRF);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_WTLS_PRE_MASTER_KEY_GEN)</code>
   */
  public static final Mechanism WTLS_PRE_MASTER_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_WTLS_PRE_MASTER_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE)</code>
   */
  public static final Mechanism WTLS_MASTER_KEY_DERIVE = new Mechanism(
      PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC)</code>
   */
  public static final Mechanism WTLS_MASTER_KEY_DERIVE_DH_ECC = new Mechanism(
      PKCS11Constants.CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_WTLS_PRF)</code>
   */
  public static final Mechanism WTLS_PRF = new Mechanism(PKCS11Constants.CKM_WTLS_PRF);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE)</code>
   */
  public static final Mechanism WTLS_SERVER_KEY_AND_MAC_DERIVE = new Mechanism(
      PKCS11Constants.CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE)</code>
   */
  public static final Mechanism WTLS_CLIENT_KEY_AND_MAC_DERIVE = new Mechanism(
      PKCS11Constants.CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SSL3_MD5_MAC)</code>
   */
  public static final Mechanism SSL3_MD5_MAC = new Mechanism(
      PKCS11Constants.CKM_SSL3_MD5_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SSL3_SHA1_MAC)</code>
   */
  public static final Mechanism SSL3_SHA1_MAC = new Mechanism(
      PKCS11Constants.CKM_SSL3_SHA1_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD5_KEY_DERIVATION)</code>
   */
  public static final Mechanism MD5_KEY_DERIVATION = new Mechanism(
      PKCS11Constants.CKM_MD5_KEY_DERIVATION);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_MD2_KEY_DERIVATION)</code>
   */
  public static final Mechanism MD2_KEY_DERIVATION = new Mechanism(
      PKCS11Constants.CKM_MD2_KEY_DERIVATION);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA1_KEY_DERIVATION)</code>
   */
  public static final Mechanism SHA1_KEY_DERIVATION = new Mechanism(
      PKCS11Constants.CKM_SHA1_KEY_DERIVATION);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA256_KEY_DERIVATION)</code>
   */
  public static final Mechanism SHA256_KEY_DERIVATION = new Mechanism(
      PKCS11Constants.CKM_SHA256_KEY_DERIVATION);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA384_KEY_DERIVATION)</code>
   */
  public static final Mechanism SHA384_KEY_DERIVATION = new Mechanism(
      PKCS11Constants.CKM_SHA384_KEY_DERIVATION);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SHA512_KEY_DERIVATION)</code>
   */
  public static final Mechanism SHA512_KEY_DERIVATION = new Mechanism(
      PKCS11Constants.CKM_SHA512_KEY_DERIVATION);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_MD2_DES_CBC)</code>
   */
  public static final Mechanism PBE_MD2_DES_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_MD2_DES_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_MD5_DES_CBC)</code>
   */
  public static final Mechanism PBE_MD5_DES_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_MD5_DES_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_MD5_CAST_CBC)</code>
   */
  public static final Mechanism PBE_MD5_CAST_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_MD5_CAST_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_MD5_CAST3_CBC)</code>
   */
  public static final Mechanism PBE_MD5_CAST3_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_MD5_CAST3_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_MD5_CAST5_CBC)</code>
   */
  public static final Mechanism PBE_MD5_CAST5_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_MD5_CAST5_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_MD5_CAST128_CBC)</code>
   */
  public static final Mechanism PBE_MD5_CAST128_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_MD5_CAST128_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_CAST5_CBC)</code>
   */
  public static final Mechanism PBE_SHA1_CAST5_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_CAST5_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_CAST128_CBC)</code>
   */
  public static final Mechanism PBE_SHA1_CAST128_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_CAST128_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_RC4_128)</code>
   */
  public static final Mechanism PBE_SHA1_RC4_128 = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_RC4_128);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_RC4_40)</code>
   */
  public static final Mechanism PBE_SHA1_RC4_40 = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_RC4_40);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_DES3_EDE_CBC)</code>
   */
  public static final Mechanism PBE_SHA1_DES3_EDE_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_DES3_EDE_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_DES2_EDE_CBC)</code>
   */
  public static final Mechanism PBE_SHA1_DES2_EDE_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_DES2_EDE_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_RC2_128_CBC)</code>
   */
  public static final Mechanism PBE_SHA1_RC2_128_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_RC2_128_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBE_SHA1_RC2_40_CBC)</code>
   */
  public static final Mechanism PBE_SHA1_RC2_40_CBC = new Mechanism(
      PKCS11Constants.CKM_PBE_SHA1_RC2_40_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PKCS5_PBKD2)</code>
   */
  public static final Mechanism PKCS5_PBKD2 = new Mechanism(
      PKCS11Constants.CKM_PKCS5_PBKD2);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_PBA_SHA1_WITH_SHA1_HMAC)</code>
   */
  public static final Mechanism PBA_SHA1_WITH_SHA1_HMAC = new Mechanism(
      PKCS11Constants.CKM_PBA_SHA1_WITH_SHA1_HMAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_KEY_WRAP_LYNKS)</code>
   */
  public static final Mechanism KEY_WRAP_LYNKS = new Mechanism(
      PKCS11Constants.CKM_KEY_WRAP_LYNKS);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_KEY_WRAP_SET_OAEP)</code>
   */
  public static final Mechanism KEY_WRAP_SET_OAEP = new Mechanism(
      PKCS11Constants.CKM_KEY_WRAP_SET_OAEP);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_KEY_GEN)</code>
   */
  public static final Mechanism SKIPJACK_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_ECB64)</code>
   */
  public static final Mechanism SKIPJACK_ECB64 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_ECB64);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_CBC64)</code>
   */
  public static final Mechanism SKIPJACK_CBC64 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_CBC64);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_OFB64)</code>
   */
  public static final Mechanism SKIPJACK_OFB64 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_OFB64);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_CFB64)</code>
   */
  public static final Mechanism SKIPJACK_CFB64 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_CFB64);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_CFB32)</code>
   */
  public static final Mechanism SKIPJACK_CFB32 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_CFB32);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_CFB16)</code>
   */
  public static final Mechanism SKIPJACK_CFB16 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_CFB16);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_CFB8)</code>
   */
  public static final Mechanism SKIPJACK_CFB8 = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_CFB8);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_WRAP)</code>
   */
  public static final Mechanism SKIPJACK_WRAP = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_WRAP);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_PRIVATE_WRAP)</code>
   */
  public static final Mechanism SKIPJACK_PRIVATE_WRAP = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_PRIVATE_WRAP);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_SKIPJACK_RELAYX)</code>
   */
  public static final Mechanism SKIPJACK_RELAYX = new Mechanism(
      PKCS11Constants.CKM_SKIPJACK_RELAYX);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_KEA_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism KEA_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_KEA_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_KEA_KEY_DERIVE)</code>
   */
  public static final Mechanism KEA_KEY_DERIVE = new Mechanism(
      PKCS11Constants.CKM_KEA_KEY_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_FORTEZZA_TIMESTAMP)</code>
   */
  public static final Mechanism FORTEZZA_TIMESTAMP = new Mechanism(
      PKCS11Constants.CKM_FORTEZZA_TIMESTAMP);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_KEY_GEN)</code>
   */
  public static final Mechanism BATON_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_BATON_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_ECB128)</code>
   */
  public static final Mechanism BATON_ECB128 = new Mechanism(
      PKCS11Constants.CKM_BATON_ECB128);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_ECB96)</code>
   */
  public static final Mechanism BATON_ECB96 = new Mechanism(
      PKCS11Constants.CKM_BATON_ECB96);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_CBC128)</code>
   */
  public static final Mechanism BATON_CBC128 = new Mechanism(
      PKCS11Constants.CKM_BATON_CBC128);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_COUNTER)</code>
   */
  public static final Mechanism BATON_COUNTER = new Mechanism(
      PKCS11Constants.CKM_BATON_COUNTER);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_SHUFFLE)</code>
   */
  public static final Mechanism BATON_SHUFFLE = new Mechanism(
      PKCS11Constants.CKM_BATON_SHUFFLE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BATON_WRAP)</code>
   */
  public static final Mechanism BATON_WRAP = new Mechanism(PKCS11Constants.CKM_BATON_WRAP);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_ECDSA_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism ECDSA_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_ECDSA_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_EC_KEY_PAIR_GEN)</code>
   */
  public static final Mechanism EC_KEY_PAIR_GEN = new Mechanism(
      PKCS11Constants.CKM_EC_KEY_PAIR_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_ECDSA)</code>
   */
  public static final Mechanism ECDSA = new Mechanism(PKCS11Constants.CKM_ECDSA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_ECDSA_SHA1)</code>
   */
  public static final Mechanism ECDSA_SHA1 = new Mechanism(PKCS11Constants.CKM_ECDSA_SHA1);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_ECDH1_DERIVE)</code>
   */
  public static final Mechanism ECDH1_DERIVE = new Mechanism(
      PKCS11Constants.CKM_ECDH1_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_ECDH1_COFACTOR_DERIVE)</code>
   */
  public static final Mechanism ECDH1_COFACTOR_DERIVE = new Mechanism(
      PKCS11Constants.CKM_ECDH1_COFACTOR_DERIVE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_ECMQV_DERIVE)</code>
   */
  public static final Mechanism ECMQV_DERIVE = new Mechanism(
      PKCS11Constants.CKM_ECMQV_DERIVE);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_JUNIPER_KEY_GEN)</code>
   */
  public static final Mechanism JUNIPER_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_JUNIPER_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_JUNIPER_ECB128)</code>
   */
  public static final Mechanism JUNIPER_ECB128 = new Mechanism(
      PKCS11Constants.CKM_JUNIPER_ECB128);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_JUNIPER_CBC128)</code>
   */
  public static final Mechanism JUNIPER_CBC128 = new Mechanism(
      PKCS11Constants.CKM_JUNIPER_CBC128);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_JUNIPER_COUNTER)</code>
   */
  public static final Mechanism JUNIPER_COUNTER = new Mechanism(
      PKCS11Constants.CKM_JUNIPER_COUNTER);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_JUNIPER_SHUFFLE)</code>
   */
  public static final Mechanism JUNIPER_SHUFFLE = new Mechanism(
      PKCS11Constants.CKM_JUNIPER_SHUFFLE);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_JUNIPER_WRAP)</code>
   */
  public static final Mechanism JUNIPER_WRAP = new Mechanism(
      PKCS11Constants.CKM_JUNIPER_WRAP);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_FASTHASH)</code>
   */
  public static final Mechanism FASTHASH = new Mechanism(PKCS11Constants.CKM_FASTHASH);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN)</code>
   */
  public static final Mechanism AES_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_AES_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_ECB)</code>
   */
  public static final Mechanism AES_ECB = new Mechanism(PKCS11Constants.CKM_AES_ECB);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_CBC)</code>
   */
  public static final Mechanism AES_CBC = new Mechanism(PKCS11Constants.CKM_AES_CBC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_MAC)</code>
   */
  public static final Mechanism AES_MAC = new Mechanism(PKCS11Constants.CKM_AES_MAC);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_MAC_GENERAL)</code>
   */
  public static final Mechanism AES_MAC_GENERAL = new Mechanism(
      PKCS11Constants.CKM_AES_MAC_GENERAL);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_CBC_PAD)</code>
   */
  public static final Mechanism AES_CBC_PAD = new Mechanism(
      PKCS11Constants.CKM_AES_CBC_PAD);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BLOWFISH_KEY_GEN)</code>
   */
  public static final Mechanism BLOWFISH_KEY_GEN = new Mechanism(
      PKCS11Constants.CKM_BLOWFISH_KEY_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_BLOWFISH_CBC)</code>
   */
  public static final Mechanism BLOWFISH_CBC = new Mechanism(
      PKCS11Constants.CKM_BLOWFISH_CBC);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DSA_PARAMETER_GEN)</code>
   */
  public static final Mechanism DSA_PARAMETER_GEN = new Mechanism(
      PKCS11Constants.CKM_DSA_PARAMETER_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DH_PKCS_PARAMETER_GEN)</code>
   */
  public static final Mechanism DH_PKCS_PARAMETER_GEN = new Mechanism(
      PKCS11Constants.CKM_DH_PKCS_PARAMETER_GEN);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_X9_42_DH_PARAMETER_GEN)</code>
   */
  public static final Mechanism X9_42_DH_PARAMETER_GEN = new Mechanism(
      PKCS11Constants.CKM_X9_42_DH_PARAMETER_GEN);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA)</code>
   */
  public static final Mechanism DES_ECB_ENCRYPT_DATA = new Mechanism(
      PKCS11Constants.CKM_DES_ECB_ENCRYPT_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA)</code>
   */
  public static final Mechanism DES_CBC_ENCRYPT_DATA = new Mechanism(
      PKCS11Constants.CKM_DES_CBC_ENCRYPT_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA)</code>
   */
  public static final Mechanism DES3_ECB_ENCRYPT_DATA = new Mechanism(
      PKCS11Constants.CKM_DES3_ECB_ENCRYPT_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA)</code>
   */
  public static final Mechanism DES3_CBC_ENCRYPT_DATA = new Mechanism(
      PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA)</code>
   */
  public static final Mechanism AES_ECB_ENCRYPT_DATA = new Mechanism(
      PKCS11Constants.CKM_AES_ECB_ENCRYPT_DATA);
  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA)</code>
   */
  public static final Mechanism AES_CBC_ENCRYPT_DATA = new Mechanism(
      PKCS11Constants.CKM_AES_CBC_ENCRYPT_DATA);

  /**
   * @deprecated use static {@link Mechanism#get} instead:
   *             <code>Mechanism.get(PKCS11Constants.CKM_VENDOR_DEFINED)</code>
   */
  public static final Mechanism VENDOR_DEFINED = new Mechanism(
      PKCS11Constants.CKM_VENDOR_DEFINED);

  /**
   * The code of the machanism as defined in PKCS11Constants (or pkcs11t.h likewise).
   */
  protected long pkcs11MechanismCode_;

  /**
   * The parameters of the mechanism. Not all mechanisms use these parameters.
   */
  protected Parameters parameters_;

  /**
   * Constructor taking just the mechansim code as defined in PKCS11Constants.
   * 
   * @param pkcs11MechanismCode
   *          The mechanism code.
   */
  public Mechanism(long pkcs11MechanismCode) {
    pkcs11MechanismCode_ = pkcs11MechanismCode;
  }

  /**
   * Gets the mechanism specified by the given mechanism code. Helper {@link PKCS11Constants} is
   * available.
   * 
   * @param pkcs11MechanismCode
   *          the pkcs11 mechanism code
   * @return the mechanism
   */
  public static Mechanism get(long pkcs11MechanismCode) {
    return new Mechanism(pkcs11MechanismCode);
  }

  /**
   * Makes a clone of this object.
   * 
   * @return A shallow clone of this object.
   * 
   * @postconditions (result <> null)
   */
  public Object clone() {
    Mechanism clone = null;

    try {
      clone = (Mechanism) super.clone();
    } catch (CloneNotSupportedException ex) {
      // this must not happen according to Java specifications
    }

    return clone;
  }

  /**
   * Override equals to check for the equality of mechanism code and parameter.
   * 
   * @param otherObject
   *          The other Mechanism object.
   * @return True, if other is an instance of this class and pkcs11MechanismCode_ and parameter_ of
   *         both objects are equal.
   */
  public boolean equals(Object otherObject) {
    boolean euqal = false;

    if (otherObject instanceof Mechanism) {
      Mechanism other = (Mechanism) otherObject;
      euqal = (this == other)
          || (this.pkcs11MechanismCode_ == other.pkcs11MechanismCode_)
          && (((this.parameters_ == null) && other.parameters_ == null) || ((this.parameters_ != null) && this.parameters_
              .equals(other.parameters_)));
    }

    return euqal;
  }

  /**
   * Override hashCode to ensure that hashtable still works after overriding equals.
   * 
   * @return The hash code of this object. Taken from the mechanism code.
   */
  public int hashCode() {
    return (int) pkcs11MechanismCode_;
  }

  /**
   * This method checks, if this mechanism is a digest mechanism. This is the information as
   * provided by the table on page 229 of the PKCS#11 v2.11 standard. If this method returns true,
   * the mechanism can be used with the digest functions.
   * 
   * @return True, if this mechanism is a digest mechanism. False, otherwise.
   */
  public boolean isDigestMechanism() {
    return Functions.isDigestMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a full encrypt/decrypt mechanism; i.e. it supports the
   * encryptUpdate() and decryptUpdate() functions. This is the information as provided by the table
   * on page 229 of the PKCS#11 v2.11 standard. If this method returns true, the mechanism can be
   * used with the encrypt and decrypt functions including encryptUpdate and decryptUpdate.
   * 
   * @return True, if this mechanism is a full encrypt/decrypt mechanism. False, otherwise.
   */
  public boolean isFullEncryptDecryptMechanism() {
    return Functions.isFullEncryptDecryptMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a full sign/verify mechanism; i.e. it supports the
   * signUpdate() and verifyUpdate() functions. This is the information as provided by the table on
   * page 229 of the PKCS#11 v2.11 standard. If this method returns true, the mechanism can be used
   * with the sign and verify functions including signUpdate and verifyUpdate.
   * 
   * @return True, if thï¿½s mechanism is a full sign/verify mechanism. False, otherwise.
   */
  public boolean isFullSignVerifyMechanism() {
    return Functions.isFullSignVerifyMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a key derivation mechanism. This is the information as
   * provided by the table on page 229 of the PKCS#11 v2.11 standard. If this method returns true,
   * the mechanism can be used with the deriveKey function.
   * 
   * @return True, if this mechanism is a key derivation mechanism. False, otherwise.
   */
  public boolean isKeyDerivationMechanism() {
    return Functions.isKeyDerivationMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a key generation mechanism for generating symmetric
   * keys. This is the information as provided by the table on page 229 of the PKCS#11 v2.11
   * standard. If this method returns true, the mechanism can be used with the generateKey function.
   * 
   * @return True, if this mechanism is a key generation mechanism. False, otherwise.
   */
  public boolean isKeyGenerationMechanism() {
    return Functions.isKeyGenerationMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a key-pair generation mechanism for generating
   * key-pairs. This is the information as provided by the table on page 229 of the PKCS#11 v2.11
   * standard. If this method returns true, the mechanism can be used with the generateKeyPair
   * function.
   * 
   * @return True, if this mechanism is a key-pair generation mechanism. False, otherwise.
   */
  public boolean isKeyPairGenerationMechanism() {
    return Functions.isKeyPairGenerationMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a sign/verify mechanism with message recovery. This is
   * the information as provided by the table on page 229 of the PKCS#11 v2.11 standard. If this
   * method returns true, the mechanism can be used with the signRecover and verifyRecover
   * functions.
   * 
   * @return True, if this mechanism is a sign/verify mechanism with message recovery. False,
   *         otherwise.
   */
  public boolean isSignVerifyRecoverMechanism() {
    return Functions.isSignVerifyRecoverMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a single-operation encrypt/decrypt mechanism; i.e. it
   * does not support the encryptUpdate() and decryptUpdate() functions. This is the information as
   * provided by the table on page 229 of the PKCS#11 v2.11 standard. If this method returns true,
   * the mechanism can be used with the encrypt and decrypt functions excluding encryptUpdate and
   * decryptUpdate.
   * 
   * @return True, if this mechanism is a single-operation encrypt/decrypt mechanism. False,
   *         otherwise.
   */
  public boolean isSingleOperationEncryptDecryptMechanism() {
    return Functions.isSingleOperationEncryptDecryptMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a single-operation sign/verify mechanism; i.e. it does
   * not support the signUpdate() and encryptUpdate() functions. This is the information as provided
   * by the table on page 229 of the PKCS#11 v2.11 standard. If this method returns true, the
   * mechanism can be used with the sign and verify functions excluding signUpdate and
   * encryptUpdate.
   * 
   * @return True, if this mechanism is a single-operation sign/verify mechanism. False, otherwise.
   */
  public boolean isSingleOperationSignVerifyMechanism() {
    return Functions.isSingleOperationSignVerifyMechanism(pkcs11MechanismCode_);
  }

  /**
   * This method checks, if this mechanism is a wrap/unwrap mechanism; i.e. it supports the
   * wrapKey() and unwrapKey() functions. This is the information as provided by the table on page
   * 229 of the PKCS#11 v2.11 standard. If this method returns true, the mechanism can be used with
   * the wrapKey and unwrapKey functions.
   * 
   * @return True, if this mechanism is a wrap/unwrap mechanism. False, otherwise.
   */
  public boolean isWrapUnwrapMechanism() {
    return Functions.isWrapUnwrapMechanism(pkcs11MechanismCode_);
  }

  /**
   * Get the parameters object of this mechanism.
   * 
   * @return The parameters of this mechansim. May be null.
   */
  public Parameters getParameters() {
    return parameters_;
  }

  /**
   * Set the parameters for this mechanism.
   * 
   * @param parameters
   *          The mechanism parameters to set.
   */
  public void setParameters(Parameters parameters) {
    parameters_ = parameters;
  }

  /**
   * Get the code of this mechanism as defined in PKCS11Constants (of pkcs11t.h likewise).
   * 
   * @return The code of this mechnism.
   */
  public long getMechanismCode() {
    return pkcs11MechanismCode_;
  }

  /**
   * Get the name of this mechanism.
   * 
   * @return The name of this mechnism.
   */
  public String getName() {
    return Functions.mechanismCodeToString(pkcs11MechanismCode_);
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of this object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer(128);

    buffer.append(Constants.INDENT);
    buffer.append("Mechanism: ");
    buffer.append(Functions.mechanismCodeToString(pkcs11MechanismCode_));
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Parameters: ");
    buffer.append(Constants.NEWLINE);
    buffer.append(parameters_);
    // buffer.append(Constants.NEWLINE);

    return buffer.toString();
  }

}
