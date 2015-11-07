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
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.DesCbcEncryptDataParameters;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

import demo.pkcs.pkcs11.wrapper.util.Util;

/**
 * This demo program shows how to derive a DES3 key.
 */
public class DeriveKeyDemo {

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
   * Usage: DeriveKeyDemo PKCS#11-module [slot-id] [pin]
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Token token;
    if (1 < args.length)
      token = Util.selectToken(pkcs11Module, output_, input_, args[1]);
    else
      token = Util.selectToken(pkcs11Module, output_, input_);
    TokenInfo tokenInfo = token.getTokenInfo();

    output_
        .println("################################################################################");
    output_.println("Using token:");
    output_.println(tokenInfo);
    output_
        .println("################################################################################");

    Session session;
    if (2 < args.length)
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, args[2]);
    else
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    Mechanism keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_DES3_KEY_GEN);

    List supportedMechanisms = Arrays.asList(token.getMechanismList());
    if (!supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_DES3_KEY_GEN))) {
      output_.println("Mechanism not supported: DES3_KEY_GEN");
      return;
    }

    DES3SecretKey baseKeyTemplate = new DES3SecretKey();

    baseKeyTemplate.getDerive().setBooleanValue(Boolean.TRUE);
    // we only have a read-only session, thus we only create a session object
    baseKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
    baseKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    baseKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);
    SecretKey baseKey = (SecretKey) session.generateKey(keyGenerationMechanism,
        baseKeyTemplate);

    System.out.println("Base key: ");
    System.out.println(baseKey.toString());

    output_
        .println("################################################################################");
    output_.println("derive key");

    // DES3 Key Template
    DES3SecretKey derived3DESKeyTemplate = new DES3SecretKey();
    SecretKey derivedKeyTemplate = derived3DESKeyTemplate;

    derivedKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
    derivedKeyTemplate.getExtractable().setBooleanValue(Boolean.TRUE);

    byte[] iv = new byte[8];
    byte[] data = new byte[24];

    DesCbcEncryptDataParameters param = new DesCbcEncryptDataParameters(iv, data);
    Mechanism mechanism = Mechanism.get(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA);

    if (!supportedMechanisms.contains(Mechanism
        .get(PKCS11Constants.CKM_DES3_CBC_ENCRYPT_DATA))) {
      output_.println("Mechanism not supported: DES3_CBC_ENCRYPT_DATA");
      return;
    }

    mechanism.setParameters(param);

    System.out.println("Derivation Mechanism: ");
    output_.println(mechanism.toString());
    output_
        .println("--------------------------------------------------------------------------------");

    Key derivedKey = session.deriveKey(mechanism, baseKey, derivedKeyTemplate);

    if (derivedKey == null) {
      output_.println("Found NO key that can be used for encryption.");
      output_.flush();
      throw new TokenException("Found no encryption key!");
    }
    System.out.println("Derived key: ");
    output_.println(derivedKey.toString());

    output_
        .println("################################################################################");
    output_.println("finished");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    output_.println("Usage: DeriveKeyDemo <PKCS#11 module> [<slot-id>] [<pin>]");
    output_.println(" e.g.: DeriveKeyDemo cryptoki.dll");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
