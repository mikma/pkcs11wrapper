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

import iaik.asn1.ASN;
import iaik.asn1.ASN1Object;
import iaik.asn1.DerCoder;
import iaik.asn1.OCTET_STRING;
import iaik.asn1.ObjectID;
import iaik.asn1.structures.AlgorithmID;
import iaik.asn1.structures.Attribute;
import iaik.asn1.structures.ChoiceOfTime;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs7.DigestInfo;
import iaik.pkcs.pkcs7.IssuerAndSerialNumber;
import iaik.pkcs.pkcs7.SignedData;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.x509.X509Certificate;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;

import demo.pkcs.pkcs11.wrapper.adapters.KeyAndCertificate;
import demo.pkcs.pkcs11.wrapper.util.CreateKeysAndCertificate;
import demo.pkcs.pkcs11.wrapper.util.Util;

/**
 * Creates a signature on a token. The hash is calculated outside the token. The signed data and the
 * signature are encoded into a PKCS#7 signed data object. This implementation just uses raw RSA.
 */
public class SignDataAndOutputInPKCS7Format {

  static PrintWriter output_;

  static BufferedReader input_;

  static Module pkcs11Module_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("GetInfo_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: SignDataAndOutputInPKCS7Format PKCS#11-module file-to-be-signed PKCS#7-signed-data-file
   * [slot-id] [pin] [bot]
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 3) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    String slot = ((args.length > 3) ? args[3] : null);
    String pin = ((args.length > 4) ? args[4] : null);
    Session session = initModuleAndGetSession(args[0], slot, pin);

    // first we search for private RSA keys that we can use for signing
    RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
    privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);

    boolean bot = false;
    if (5 < args.length)
      bot = true;

    KeyAndCertificate selectedSignatureKeyAndCertificate = null;
    boolean found = false;
    while (!found) {
      selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(session,
          privateSignatureKeyTemplate, output_, input_, bot);
      if (selectedSignatureKeyAndCertificate != null
          && selectedSignatureKeyAndCertificate.getCertificate() != null) {
        found = true;
      }
      if (!found) {
        // no key with corresponding certificate -> create them with other demo
        session.closeSession();
        pkcs11Module_.finalize(null);
        if (args.length > 4)
          CreateKeysAndCertificate.main(new String[] { args[0],
              "CN=myname,O=IAIK,C=AT,EMAIL=myname@iaik.at", args[3], args[4] });
        else if (args.length > 3)
          CreateKeysAndCertificate.main(new String[] { args[0],
              "CN=myname,O=IAIK,C=AT,EMAIL=myname@iaik.at", args[3] });
        else
          CreateKeysAndCertificate.main(new String[] { args[0],
              "CN=myname,O=IAIK,C=AT,EMAIL=myname@iaik.at" });
        session = initModuleAndGetSession(args[0], slot, pin);
      }
    }

    PrivateKey selectedSignatureKey = (PrivateKey) selectedSignatureKeyAndCertificate
        .getKey();
    X509PublicKeyCertificate pkcs11SignerCertificate = selectedSignatureKeyAndCertificate
        .getCertificate();
    X509Certificate signerCertificate = (pkcs11SignerCertificate != null) ? new X509Certificate(
        pkcs11SignerCertificate.getValue().getByteArrayValue()) : null;

    // here the interesting code starts

    output_
        .println("################################################################################");
    output_.println("signing data from file: " + args[1]);

    InputStream dataInputStream = new FileInputStream(args[1]);

    // we do digesting outside the card, because some cards do not support on-card hashing
    MessageDigest digestEngine = MessageDigest.getInstance("SHA-1");

    // we buffer the content to have it after hashing for the PKCS#7 content
    ByteArrayOutputStream contentBuffer = new ByteArrayOutputStream();
    byte[] dataBuffer = new byte[1024];
    int bytesRead;

    // feed all data from the input stream to the message digest
    while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
      // hash the data
      digestEngine.update(dataBuffer, 0, bytesRead);
      // and buffer the data
      contentBuffer.write(dataBuffer, 0, bytesRead);
    }
    byte[] contentHash = digestEngine.digest();
    contentBuffer.close();

    // create the SignedData
    SignedData signedData = new SignedData(contentBuffer.toByteArray(),
        SignedData.IMPLICIT);
    // set the certificates
    signedData.setCertificates(new X509Certificate[] { signerCertificate });

    // create a new SignerInfo
    SignerInfo signerInfo = new SignerInfo(new IssuerAndSerialNumber(signerCertificate),
        AlgorithmID.sha1, null);

    // define the authenticated attributes
    iaik.asn1.structures.Attribute[] authenticatedAttributes = {
        new Attribute(ObjectID.contentType, new ASN1Object[] { ObjectID.pkcs7_data }),
        new Attribute(ObjectID.signingTime,
            new ASN1Object[] { new ChoiceOfTime().toASN1Object() }),
        new Attribute(ObjectID.messageDigest, new ASN1Object[] { new OCTET_STRING(
            contentHash) }) };
    // set the authenticated attributes
    signerInfo.setAuthenticatedAttributes(authenticatedAttributes);

    // encode the authenticated attributes, which is the data that we must sign
    byte[] toBeSigned = DerCoder.encode(ASN.createSetOf(authenticatedAttributes, true));

    // we do digesting outside the card, because some cards do not support on-card hashing
    // we can use the digest engine from above
    byte[] hashToBeSigned = digestEngine.digest(toBeSigned);

    // according to PKCS#11 building the DigestInfo structure must be done off-card
    DigestInfo digestInfoEngine = new DigestInfo(AlgorithmID.sha1, hashToBeSigned);

    byte[] toBeEncrypted = digestInfoEngine.toByteArray();

    // initialize for signing
    session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), selectedSignatureKey);

    // sign the data to be signed
    byte[] signatureValue = session.sign(toBeEncrypted);

    // set the signature value in the signer info
    signerInfo.setEncryptedDigest(signatureValue);

    // and add the signer info object to the PKCS#7 signed data object
    signedData.addSignerInfo(signerInfo);

    output_.println("Writing signature to file: " + args[2]);

    OutputStream signatureOutput = new FileOutputStream(args[2]);
    signedData.writeTo(signatureOutput);
    signatureOutput.flush();
    signatureOutput.close();

    output_
        .println("################################################################################");

    session.closeSession();
    pkcs11Module_.finalize(null);
  }

  private static Session initModuleAndGetSession(String pkcs11Module, String slot,
      String pin) throws Exception {
    pkcs11Module_ = Module.getInstance(pkcs11Module);
    pkcs11Module_.initialize(null);

    Token token;
    if (slot != null)
      token = Util.selectToken(pkcs11Module_, output_, input_, slot);
    else
      token = Util.selectToken(pkcs11Module_, output_, input_);
    if (token == null) {
      output_.println("We have no token to proceed. Finished.");
      output_.flush();
      throw new TokenException("No token found!");
    }

    List supportedMechanisms = Arrays.asList(token.getMechanismList());
    if (!supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
      output_.print("This token does not support raw RSA signing!");
      output_.flush();
      throw new TokenException("RSA not supported!");
    } else {
      MechanismInfo rsaMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS));
      if (!rsaMechanismInfo.isSign()) {
        output_.print("This token does not support RSA signing according to PKCS!");
        output_.flush();
        throw new TokenException("RSA signing not supported!");
      }
    }

    Session session;
    if (pin != null)
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, pin);
    else
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    return session;
  }

  public static void printUsage() {
    output_
        .println("Usage: SignDataAndOutputInPKCS7Format <PKCS#11 module> <file to be signed> <PKCS#7 signed data file> [<slot-id>] [<pin>] [bot]");
    output_
        .println(" e.g.: SignDataAndOutputInPKCS7Format pk2priv.dll data.dat signedData.p7");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
