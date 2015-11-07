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

package demo.pkcs.pkcs11.wrapper.hashes;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This demo program uses a PKCS#11 module to calculate a hash of a given file. Optionally the
 * calcualted raw hash can be written to file. The program also verifies the calculated hash with a
 * software hash from Java.
 */
public class Digest {

  /**
   * Usage: Digest PKCS#11-module file-to-be-digested [digest-value-file slot-index user-PIN]
   */
  public static void main(String[] args) throws IOException, TokenException,
      NoSuchAlgorithmException {
    if (args.length < 2) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

    if (slots.length == 0) {
      System.out.println("No slot with present token found!");
      throw new TokenException("No token found!");
    }

    Slot selectedSlot;
    if (3 < args.length)
      selectedSlot = slots[Integer.parseInt(args[3])];
    else
      selectedSlot = slots[0];
    Token token = selectedSlot.getToken();

    Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
        Token.SessionReadWriteBehavior.RO_SESSION, null, null);

    // some tokens require login
    if (args.length > 4)
      session.login(Session.UserType.USER, args[4].toCharArray());

    System.out
        .println("################################################################################");
    System.out.println("digesting data from file: " + args[1]);

    // be sure that your token can process the specified mechanism
    Mechanism digestMechanism = Mechanism.get(PKCS11Constants.CKM_SHA_1);

    byte[] dataBuffer = new byte[4096];
    byte[] helpBuffer;
    int bytesRead;

    FileInputStream dataInputStream = new FileInputStream(args[1]);

    int updateCounter = 0;
    long t0 = System.currentTimeMillis();

    // initialize for digesting
    session.digestInit(digestMechanism);
    // feed in all data from the input stream
    while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
      if (bytesRead < dataBuffer.length) {
        helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for
                                          // digesting
        System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
        session.digestUpdate(helpBuffer);
      } else {
        session.digestUpdate(dataBuffer);
      }
      updateCounter++;
    }
    byte[] digestValue = session.digestFinal();

    long t1 = System.currentTimeMillis();

    dataInputStream.close();

    Arrays.fill(dataBuffer, (byte) 0); // ensure that no data is left in the memory

    System.out.println("The digest value is: "
        + new BigInteger(1, digestValue).toString(16));
    System.out.println("Calculation took " + (t1 - t0) + " milliseconds using "
        + updateCounter + " update calls.");

    if (args.length == 2) {
      System.out.println("Writing digest value to file: " + args[2]);

      FileOutputStream signatureOutput = new FileOutputStream(args[2]);
      signatureOutput.write(digestValue);
      signatureOutput.flush();
      signatureOutput.close();
    }

    System.out
        .println("################################################################################");

    System.out
        .println("################################################################################");
    System.out.println("verifying digest with software digest");

    MessageDigest softwareDigestEngine = MessageDigest.getInstance("SHA-1");

    dataInputStream = new FileInputStream(args[1]);

    updateCounter = 0;
    t0 = System.currentTimeMillis();

    // feed in all data from the input stream
    while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
      softwareDigestEngine.update(dataBuffer, 0, bytesRead);
      updateCounter++;
    }
    byte[] softwareDigestValue = softwareDigestEngine.digest();

    t1 = System.currentTimeMillis();

    dataInputStream.close();

    Arrays.fill(dataBuffer, (byte) 0); // ensure that no data is left in the memory

    System.out.println("The digest value is: "
        + new BigInteger(1, softwareDigestValue).toString(16));
    System.out.println("Calculation took " + (t1 - t0) + " milliseconds using "
        + updateCounter + " update calls.");

    if (Arrays.equals(digestValue, softwareDigestValue)) {
      System.out.println("Verified Message Digest successfully");
    } else {
      System.out.println("Verification of Message Digest FAILED");
    }

    System.out
        .println("################################################################################");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    System.out
        .println("Usage: Digest <PKCS#11 module> <file to be digested> [<digest value file> <slot-index> <user-PIN>]");
    System.out.println(" e.g.: Digest pk2priv.dll data.dat digest.bin");
    System.out.println("The given DLL must be in the search path of the system.");
  }

}
