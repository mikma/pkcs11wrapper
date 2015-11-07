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

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.MechanismInfo;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs7.DigestInfo;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

import demo.pkcs.pkcs11.wrapper.adapters.KeyAndCertificate;
import demo.pkcs.pkcs11.wrapper.util.Util;

/**
 * Creates and verifies a signature on a token. The hash is calculated outside the token. Notice
 * that many tokens do not support verification. In this case you will get an exception when the
 * program tries to verify the signature on the token.
 */
public class SignAndVerify {

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
   * Usage: SignAndVerify PKCS#11-module file-to-be-signed [signature-value-file] [slot-id] [pin]
   * [bot]
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Token token;
    if (3 < args.length)
      token = Util.selectToken(pkcs11Module, output_, input_, args[3]);
    else
      token = Util.selectToken(pkcs11Module, output_, input_);
    if (token == null) {
      output_.println("We have no token to proceed. Finished.");
      output_.flush();
      throw new Exception("We have no token to proceed.");
    }

    // first check out what attributes of the keys we may set
    Mechanism[] mechanisms = token.getMechanismList();
    Hashtable supportedMechanisms = new Hashtable(mechanisms.length);
    for (int i = 0; i < mechanisms.length; i++) {
      supportedMechanisms.put(mechanisms[i], mechanisms[i]);
    }

    MechanismInfo signatureMechanismInfo;
    if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS))) {
      signatureMechanismInfo = token.getMechanismInfo(Mechanism
          .get(PKCS11Constants.CKM_RSA_PKCS));
    } else {
      signatureMechanismInfo = null;
      output_.println("The token does not support mechanism RSA_PKCS. Going to exit.");
      throw new Exception("The token does not support mechanism RSA_PKCS.");
    }

    if ((signatureMechanismInfo == null) || !signatureMechanismInfo.isSign()) {
      output_
          .println("The token does not support signing with mechanism RSA_PKCS. Going to exit.");
      throw new Exception("The token does not support signing with mechanism RSA_PKCS.");
    }

    Session session;
    if (4 < args.length)
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, args[4]);
    else
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    output_
        .println("################################################################################");
    output_.println("find private signature key");
    RSAPrivateKey templateSignatureKey = new RSAPrivateKey();
    templateSignatureKey.getSign().setBooleanValue(Boolean.TRUE);

    boolean bot = false;
    if (5 < args.length)
      bot = true;

    KeyAndCertificate selectedSignatureKeyAndCertificate = Util.selectKeyAndCertificate(
        session, templateSignatureKey, output_, input_, bot);
    if (selectedSignatureKeyAndCertificate == null) {
      output_.println("We have no signature key to proceed. Finished.");
      output_.flush();
      throw new Exception("We have no signature key to proceed. Finished.");
    }
    Key signatureKey = selectedSignatureKeyAndCertificate.getKey();
    output_
        .println("################################################################################");

    output_
        .println("################################################################################");
    output_.println("signing data from file: " + args[1]);

    InputStream dataInputStream = new FileInputStream(args[1]);

    // we do digesting outside the card, because some cards do not support on-card hashing
    MessageDigest digestEngine = MessageDigest.getInstance("SHA-1");

    // be sure that your token can process the specified mechanism
    Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
    // initialize for signing
    session.signInit(signatureMechanism, signatureKey);

    byte[] dataBuffer = new byte[1024];
    // byte[] helpBuffer;
    int bytesRead;

    // feed all data from the input stream to the message digest
    while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
      // helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for
      // signing
      // System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
      // session.signUpdate(helpBuffer);
      // Arrays.fill(helpBuffer, (byte) 0); // ensure that no data is left in the memory
      digestEngine.update(dataBuffer, 0, bytesRead);
    }
    byte[] digest = digestEngine.digest();

    // according to PKCS#11 building the DigestInfo structure must be done off-card
    DigestInfo digestInfoObject = new DigestInfo(AlgorithmID.sha1, digest);

    byte[] digestInfo = digestInfoObject.toByteArray();

    byte[] signatureValue = session.sign(digestInfo);

    // Arrays.fill(dataBuffer, (byte) 0); // ensure that no data is left in the memory

    output_.println("The siganture value is: "
        + new BigInteger(1, signatureValue).toString(16));

    if (args.length == 3) {
      output_.println("Writing signature to file: " + args[2]);

      OutputStream signatureOutput = new FileOutputStream(args[2]);
      signatureOutput.write(signatureValue);
      signatureOutput.flush();
      signatureOutput.close();
    }

    output_
        .println("################################################################################");

    if ((signatureMechanismInfo == null) || !signatureMechanismInfo.isVerify()) {
      output_
          .println("The token does not support verification with mechanism RSA_PKCS. Going to exit.");
      throw new Exception(
          "The token does not support verification with mechanism RSA_PKCS.");
    }

    boolean verifyInSoftware;
    output_
        .println("################################################################################");
    output_.println("find public verification key");
    RSAPublicKey templateVerificationKey = new RSAPublicKey();
    templateVerificationKey.getVerify().setBooleanValue(Boolean.TRUE);
    // we search for a public key with the same ID
    templateVerificationKey.getId().setByteArrayValue(
        signatureKey.getId().getByteArrayValue());

    session.findObjectsInit(templateVerificationKey);

    Object[] foundVerificationKeyObjects = session.findObjects(1); // find first

    RSAPublicKey verificationKey = null;
    if (foundVerificationKeyObjects.length > 0) {
      verificationKey = (RSAPublicKey) foundVerificationKeyObjects[0];
      output_
          .println("________________________________________________________________________________");
      output_.println(verificationKey);
      output_
          .println("________________________________________________________________________________");
      verifyInSoftware = false;
    } else {
      if (selectedSignatureKeyAndCertificate.getCertificate() != null) {
        output_.println("No matching public key found! Will verify in software.");
      } else {
        output_
            .println("No matching public key found and no certificate found! Going to exit.");
        throw new Exception("No matching public key found and no certificate found!");
      }
      verifyInSoftware = true;
    }
    session.findObjectsFinal();

    output_
        .println("################################################################################");

    output_
        .println("################################################################################");
    if (verifyInSoftware) {
      output_.println("verifying signature in software");
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      byte[] encodedCertificate = selectedSignatureKeyAndCertificate.getCertificate()
          .getValue().getByteArrayValue();
      X509Certificate certificate = (X509Certificate) certificateFactory
          .generateCertificate(new ByteArrayInputStream(encodedCertificate));
      Signature signatureEngine = Signature.getInstance("SHA1withRSA");

      signatureEngine.initVerify(certificate.getPublicKey());
      dataInputStream = new FileInputStream(args[1]);
      // feed all data from the input stream to the message digest
      while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
        // helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for
        // signing
        // System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
        // session.signUpdate(helpBuffer);
        // Arrays.fill(helpBuffer, (byte) 0); // ensure that no data is left in the memory
        signatureEngine.update(dataBuffer, 0, bytesRead);
      }

      try {
        if (signatureEngine.verify(signatureValue)) {
          output_.println("Verified the signature successfully");
        } else {
          output_.println("Signature Invalid.");
        }
      } catch (SignatureException ex) {
        output_.println("Verification FAILED: " + ex.getMessage());
      }
    } else {
      output_.println("verifying signature on token");

      dataInputStream = new FileInputStream(args[1]);

      // feed all data from the input stream to the message digest
      while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
        // helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for
        // signing
        // System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
        // session.signUpdate(helpBuffer);
        // Arrays.fill(helpBuffer, (byte) 0); // ensure that no data is left in the memory
        digestEngine.update(dataBuffer, 0, bytesRead);
      }
      digest = digestEngine.digest();

      // according to PKCS#11 building the DigestInfo structure must be done off-card
      digestInfoObject = new DigestInfo(AlgorithmID.sha1, digest);

      digestInfo = digestInfoObject.toByteArray();

      // be sure that your token can process the specified mechanism
      Mechanism verificationMechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS);
      // initialize for signing
      session.verifyInit(verificationMechanism, verificationKey);

      try {
        session.verify(digestInfo, signatureValue); // throws an exception upon unsuccessful
                                                    // verification
        output_.println("Verified the signature successfully");
      } catch (TokenException ex) {
        output_.println("Verification FAILED: " + ex.getMessage());
      }
    }

    output_
        .println("################################################################################");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    output_
        .println("Usage: SignAndVerify <PKCS#11 module> <file to be signed> [<signature value file>] [<slot-id>] [<pin>] [bot]");
    output_.println(" e.g.: SignAndVerify pk2priv.dll data.dat signature.bin");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
