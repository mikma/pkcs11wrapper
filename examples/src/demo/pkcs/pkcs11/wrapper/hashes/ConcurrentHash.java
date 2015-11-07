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
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * This demo program connects to two different modules and calculates hash values with both of them.
 * This program uses SHA-1. It demonstrates that it is possible to work with two independent module
 * at the same time. By now, I did not conduct any real multi-threaded tests.
 */
public class ConcurrentHash {

  /**
   * Usage: ConcurrentHash PKCS#11-module-#1 PKCS#11-module-#2 data [slot-index-module#1]
   * [slot-index-module#2]
   */
  public static void main(String[] args) throws TokenException, IOException,
      NoSuchAlgorithmException {
    if (args.length < 3) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    System.out
        .println("################################################################################");
    System.out.println("load and initialize module: " + args[0]);
    Module pkcs11Module1 = Module.getInstance(args[0]);
    pkcs11Module1.initialize(null);
    System.out.println("load and initialize module: " + args[1]);
    Module pkcs11Module2 = Module.getInstance(args[1]);
    if (!pkcs11Module1.equals(pkcs11Module2))
      pkcs11Module2.initialize(null);
    System.out
        .println("################################################################################");

    System.out
        .println("################################################################################");
    System.out.println("getting tokens");

    Slot[] slotsWithToken1 = pkcs11Module1
        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
    if (slotsWithToken1.length < 1) {
      System.err.println("No token present for module: " + pkcs11Module1.getInfo());
      throw new TokenException("No token found!");
    }

    int t1 = 0, t2 = 0;

    Slot selectedSlot;
    if (3 < args.length)
      selectedSlot = slotsWithToken1[Integer.parseInt(args[3])];
    else
      selectedSlot = slotsWithToken1[0];
    Token token1 = selectedSlot.getToken();
    System.out
        .println("________________________________________________________________________________");
    System.out.println("token #1:");
    System.out.println(token1.getTokenInfo());
    System.out
        .println("________________________________________________________________________________");

    Slot[] slotsWithToken2 = pkcs11Module2
        .getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
    if (slotsWithToken2.length < 1) {
      System.err.println("No token present for module: " + pkcs11Module2.getInfo());
      throw new TokenException("No token found!");
    }

    if (4 < args.length)
      selectedSlot = slotsWithToken2[Integer.parseInt(args[4])];
    else
      selectedSlot = slotsWithToken2[0];
    Token token2 = selectedSlot.getToken();
    System.out
        .println("________________________________________________________________________________");
    System.out.println("token #2:");
    System.out.println(token2.getTokenInfo());
    System.out
        .println("________________________________________________________________________________");
    System.out
        .println("################################################################################");

    System.out
        .println("################################################################################");
    System.out.println("opening sessions");
    Session session1 = token1.openSession(Token.SessionType.SERIAL_SESSION,
        Token.SessionReadWriteBehavior.RO_SESSION, null, null);
    Session session2 = token2.openSession(Token.SessionType.SERIAL_SESSION,
        Token.SessionReadWriteBehavior.RO_SESSION, null, null);

    // some tokens require login
    if (args.length > 6) {
      session1.login(Session.UserType.USER, args[5].toCharArray());
      if (!pkcs11Module1.equals(pkcs11Module2) || !args[3].equals(args[4]))
        session2.login(Session.UserType.USER, args[6].toCharArray());
    }

    System.out.println("opening data file: " + args[2]);
    InputStream dataInputStream = new FileInputStream(args[2]);

    // be sure that your token can process the specified mechanism
    Mechanism digestMechanism = Mechanism.get(PKCS11Constants.CKM_SHA_1);
    // initialize for digesting
    System.out.println("initializing sessions for hashing");
    session1.digestInit(digestMechanism);
    session2.digestInit(digestMechanism);

    byte[] dataBuffer = new byte[1024];
    byte[] helpBuffer;
    int bytesRead;

    // feed in all data from the input stream
    while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
      helpBuffer = new byte[bytesRead]; // we need a buffer that only holds what to send for
                                        // digesting
      System.arraycopy(dataBuffer, 0, helpBuffer, 0, bytesRead);
      session1.digestUpdate(helpBuffer);
      session2.digestUpdate(helpBuffer);
      Arrays.fill(helpBuffer, (byte) 0); // ensure that no data is left in the memory
    }
    Arrays.fill(dataBuffer, (byte) 0); // ensure that no data is left in the memory

    byte[] digestValue1 = session1.digestFinal();
    byte[] digestValue2 = session2.digestFinal();

    System.out.println("The SHA-1 hash value #1 is: "
        + new BigInteger(1, digestValue1).toString(16));
    System.out.println("The SHA-1 hash value #2 is: "
        + new BigInteger(1, digestValue2).toString(16));

    if (Arrays.equals(digestValue1, digestValue2)) {
      System.out.println("The hash values are equal.");
    } else {
      System.out.println("The hash values are different. Test failed");
    }

    System.out.println("closing sessions");
    session1.closeSession();
    session2.closeSession();
    System.out
        .println("################################################################################");

    System.out
        .println("################################################################################");
    System.out.println("verifying hash with software digest");

    MessageDigest softwareDigestEngine = MessageDigest.getInstance("SHA-1");

    dataInputStream = new FileInputStream(args[2]);

    // feed in all data from the input stream
    while ((bytesRead = dataInputStream.read(dataBuffer)) >= 0) {
      softwareDigestEngine.update(dataBuffer, 0, bytesRead);
    }
    dataInputStream.close();
    byte[] softwareDigestValue = softwareDigestEngine.digest();

    Arrays.fill(dataBuffer, (byte) 0); // ensure that no data is left in the memory

    System.out.println("The software digest value is: "
        + new BigInteger(1, softwareDigestValue).toString(16));

    if (Arrays.equals(digestValue1, softwareDigestValue)
        && Arrays.equals(digestValue2, softwareDigestValue)) {
      System.out.println("All SHA-1 hash values are equal. Test passed successfully.");
    } else {
      System.out.println("Verification of hash value FAILED!");
    }

    System.out
        .println("################################################################################");
  }

  protected static void printUsage() {
    System.out
        .println("ConcurrentHash <PKCS#11 module name #1> <PKCS#11 module name #2> <data> [<slot-index module #1>] [<slot-index module #2>]");
    System.out.println("e.g.: ConcurrentHash pk2priv.dll softtoken.dll data.dat");
    System.out
        .println("Both modules must support hashing without the user being logged in.");
  }

}
