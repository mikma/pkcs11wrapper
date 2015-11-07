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

package demo.pkcs.pkcs11.wrapper.keygeneration;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import demo.pkcs.pkcs11.wrapper.util.Util;

/**
 * This demo program generates a 2048 bit RSA key-pair on the token and writes the public key to a
 * file.
 */
public class GenerateKeyPair {

  static BufferedReader input_;

  static PrintWriter output_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("SignAndVerify_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: GenerateKeyPair PKCS#11-module X.509-encoded-public-key-file [slot-index] [pin]
   */
  public static void main(String[] args) throws IOException, TokenException,
      NoSuchAlgorithmException, InvalidKeySpecException {
    if (args.length < 2) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

    if (slots.length == 0) {
      output_.println("No slot with present token found!");
      throw new TokenException("No token found!");
    }

    Slot selectedSlot;
    if (2 < args.length)
      selectedSlot = slots[Integer.parseInt(args[2])];
    else
      selectedSlot = slots[0];
    Token token = selectedSlot.getToken();
    TokenInfo tokenInfo = token.getTokenInfo();

    output_
        .println("################################################################################");
    output_.println("Information of Token:");
    output_.println(tokenInfo);
    output_
        .println("################################################################################");

    Session session;
    if (3 < args.length)
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, args[3]);
    else
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    output_
        .println("################################################################################");
    output_.print("Generating new 2048 bit RSA key-pair... ");
    output_.flush();

    // first check out what attributes of the keys we may set
    HashSet supportedMechanisms = new HashSet(Arrays.asList(token.getMechanismList()));

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS));
    } else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_X_509))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_X_509));
    } else if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_9796))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_9796));
    } else if (supportedMechanisms.contains(Mechanism
        .get(PKCS11Constants.CKM_RSA_PKCS_OAEP))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS_OAEP));
    } else {
      signatureMechanismInfo = null;
    }

    Mechanism keyPairGenerationMechanism = Mechanism
        .get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
    RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
    RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();

    // set the general attributes for the public key
    rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(2048));
    byte[] publicExponentBytes = { 0x01, 0x00, 0x01 }; // 2^16 + 1
    rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
    rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    byte[] id = new byte[20];
    new Random().nextBytes(id);
    rsaPublicKeyTemplate.getId().setByteArrayValue(id);
    // rsaPublicKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());

    rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
    rsaPrivateKeyTemplate.getId().setByteArrayValue(id);
    // byte[] subject = args[1].getBytes();
    // rsaPrivateKeyTemplate.getSubject().setByteArrayValue(subject);
    // rsaPrivateKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());

    // set the attributes in a way netscape does, this should work with most tokens
    if (signatureMechanismInfo != null) {
      rsaPublicKeyTemplate.getVerify().setBooleanValue(
          new Boolean(signatureMechanismInfo.isVerify()));
      rsaPublicKeyTemplate.getVerifyRecover().setBooleanValue(
          new Boolean(signatureMechanismInfo.isVerifyRecover()));
      rsaPublicKeyTemplate.getEncrypt().setBooleanValue(
          new Boolean(signatureMechanismInfo.isEncrypt()));
      rsaPublicKeyTemplate.getDerive().setBooleanValue(
          new Boolean(signatureMechanismInfo.isDerive()));
      rsaPublicKeyTemplate.getWrap().setBooleanValue(
          new Boolean(signatureMechanismInfo.isWrap()));

      rsaPrivateKeyTemplate.getSign().setBooleanValue(
          new Boolean(signatureMechanismInfo.isSign()));
      rsaPrivateKeyTemplate.getSignRecover().setBooleanValue(
          new Boolean(signatureMechanismInfo.isSignRecover()));
      rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(
          new Boolean(signatureMechanismInfo.isDecrypt()));
      rsaPrivateKeyTemplate.getDerive().setBooleanValue(
          new Boolean(signatureMechanismInfo.isDerive()));
      rsaPrivateKeyTemplate.getUnwrap().setBooleanValue(
          new Boolean(signatureMechanismInfo.isUnwrap()));
    } else {
      // if we have no information we assume these attributes
      rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
      rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);

      rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
      rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
    }

    // netscape does not set these attribute, so we do no either
    rsaPublicKeyTemplate.getKeyType().setPresent(false);
    rsaPublicKeyTemplate.getObjectClass().setPresent(false);

    rsaPrivateKeyTemplate.getKeyType().setPresent(false);
    rsaPrivateKeyTemplate.getObjectClass().setPresent(false);

    KeyPair generatedKeyPair = session.generateKeyPair(keyPairGenerationMechanism,
        rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
    RSAPublicKey generatedRSAPublicKey = (RSAPublicKey) generatedKeyPair.getPublicKey();
    RSAPrivateKey generatedRSAPrivateKey = (RSAPrivateKey) generatedKeyPair
        .getPrivateKey();
    // no we may work with the keys...

    output_.println("Success");
    output_.println("The public key is");
    output_
        .println("_______________________________________________________________________________");
    output_.println(generatedRSAPublicKey);
    output_
        .println("_______________________________________________________________________________");
    output_.println("The private key is");
    output_
        .println("_______________________________________________________________________________");
    output_.println(generatedRSAPrivateKey);
    output_
        .println("_______________________________________________________________________________");

    // write the public key to file
    output_
        .println("################################################################################");
    output_.println("Writing the public key of the generated key-pair to file: "
        + args[1]);
    RSAPublicKey exportableRsaPublicKey = generatedRSAPublicKey;
    BigInteger modulus = new BigInteger(1, exportableRsaPublicKey.getModulus()
        .getByteArrayValue());
    BigInteger publicExponent = new BigInteger(1, exportableRsaPublicKey
        .getPublicExponent().getByteArrayValue());
    RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    java.security.interfaces.RSAPublicKey javaRsaPublicKey = (java.security.interfaces.RSAPublicKey) keyFactory
        .generatePublic(rsaPublicKeySpec);
    X509EncodedKeySpec x509EncodedPublicKey = (X509EncodedKeySpec) keyFactory.getKeySpec(
        javaRsaPublicKey, X509EncodedKeySpec.class);

    FileOutputStream publicKeyFileStream = new FileOutputStream(args[1]);
    publicKeyFileStream.write(x509EncodedPublicKey.getEncoded());
    publicKeyFileStream.flush();
    publicKeyFileStream.close();

    output_
        .println("################################################################################");

    // now we try to search for the generated keys
    output_
        .println("################################################################################");
    output_
        .println("Trying to search for the public key of the generated key-pair by ID: "
            + Functions.toHexString(id));
    // set the search template for the public key
    RSAPublicKey exportRsaPublicKeyTemplate = new RSAPublicKey();
    exportRsaPublicKeyTemplate.getId().setByteArrayValue(id);

    session.findObjectsInit(exportRsaPublicKeyTemplate);
    Object[] foundPublicKeys = session.findObjects(1);
    session.findObjectsFinal();

    if (foundPublicKeys.length != 1) {
      output_.println("Error: Cannot find the public key under the given ID!");
    } else {
      output_.println("Found public key!");
      output_
          .println("_______________________________________________________________________________");
      output_.println(foundPublicKeys[0]);
      output_
          .println("_______________________________________________________________________________");
    }

    output_
        .println("################################################################################");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    output_
        .println("Usage: GenerateKeyPair <PKCS#11 module> <X.509 encoded public key file> [<slot-index>] [<pin>]");
    output_.println(" e.g.: GenerateKeyPair pk2priv.dll publicKey.xpk");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
