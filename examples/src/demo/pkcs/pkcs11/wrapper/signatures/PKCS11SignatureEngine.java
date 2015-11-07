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

package demo.pkcs.pkcs11.wrapper.signatures;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import demo.pkcs.pkcs11.wrapper.adapters.TokenPrivateKey;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs7.DigestInfo;

/**
 * This is an implementation of a JCA Signature class that uses the PKCS#11 wrapper to create the
 * signature. This implementation hashes outside the token (i.e. in software) and support only
 * signing but not verification.
 */
public class PKCS11SignatureEngine extends Signature {

  /**
   * The session that this object uses for signing with the token.
   */
  protected Session session_;

  /**
   * The mechanism that this object uses for signing with the token.
   */
  protected Mechanism signatureMechanism_;

  /**
   * The PKCS#11 key that this object uses for signing with the token.
   */
  protected Key signatureKey_;

  /**
   * The hash algorithm to use for hashing the data.
   */
  protected AlgorithmID hashAlgorithm_;

  /**
   * The digest engine used to hash the data.
   */
  protected MessageDigest digestEngine_;

  /**
   * Creates a new signature engine that uses the given parameters to create the signature on the
   * PKCS#11 token.
   * 
   * @param algorithmName
   *          The name of the signature algorithm. This class does not interpret this name; it uses
   *          it as is.
   * @param session
   *          The PKCS#11 session to use for signing. It must have the permissions to sign with the
   *          used private key; e.g. it may require a user session.
   * @param signatureMechanism
   *          The PKCS#11 mechanism to use for signing; e.g. Mechanism.RSA_PKCS.
   * @param hashAlgorithm
   *          The hash algorithm to use for hashing the data; e.g. AlgorithmID.sha1.
   * @exception NoSuchAlgorithmException
   *              If the hash algorithm is not available.
   */
  public PKCS11SignatureEngine(String algorithmName, Session session,
      Mechanism signatureMechanism, AlgorithmID hashAlgorithm)
      throws NoSuchAlgorithmException {
    super(algorithmName);
    session_ = session;
    signatureMechanism_ = signatureMechanism;
    hashAlgorithm_ = hashAlgorithm;
    // we do digesting outside the card, because some cards do not support on-card hashing
    digestEngine_ = hashAlgorithm_.getMessageDigestInstance();
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected boolean engineVerify(byte[] signatureValue) throws SignatureException {
    throw new UnsupportedOperationException();
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected java.lang.Object engineGetParameter(String name)
      throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected void engineSetParameter(String param, java.lang.Object value)
      throws InvalidParameterException {
    throw new UnsupportedOperationException();
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected void engineInitSign(java.security.PrivateKey privateKey)
      throws InvalidKeyException {
    if (!(privateKey instanceof TokenPrivateKey)) {
      throw new InvalidKeyException("Private key must be of instance InvalidKeyException");
    }
    signatureKey_ = ((TokenPrivateKey) privateKey).getTokenPrivateKey();
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected byte[] engineSign() throws SignatureException {
    byte[] hashToBeSigned = digestEngine_.digest();

    // according to PKCS#11 building the DigestInfo structure must be done off-card
    DigestInfo digestInfoEngine = new DigestInfo(AlgorithmID.sha1, hashToBeSigned);

    byte[] toBeEncrypted = digestInfoEngine.toByteArray();

    byte[] signatureValue = null;
    try {
      // initialize for signing
      session_.signInit(signatureMechanism_, signatureKey_);

      // sign the data to be signed
      signatureValue = session_.sign(toBeEncrypted);
    } catch (TokenException ex) {
      throw new SignatureException(ex.toString());
    }

    return signatureValue;
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected void engineInitVerify(java.security.PublicKey publicKey)
      throws InvalidKeyException {
    throw new UnsupportedOperationException();
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected void engineUpdate(byte dataByte) throws SignatureException {
    digestEngine_.update(dataByte);
  }

  /**
   * SPI: see documentation of java.security.Signature.
   */
  protected void engineUpdate(byte[] data, int offset, int length)
      throws SignatureException {
    digestEngine_.update(data, offset, length);
  }

}
