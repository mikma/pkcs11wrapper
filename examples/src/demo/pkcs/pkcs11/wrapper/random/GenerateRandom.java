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

package demo.pkcs.pkcs11.wrapper.random;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * This demo program uses a PKCS#11 module to produce random data. Optionally the random data can be
 * written to file.
 */
public class GenerateRandom {

  /**
   * Usage: GenerateRandom PKCS#11-module number-of-bytes [output-file slot-index user-PIN]
   */
  public static void main(String[] args) throws IOException, TokenException {
    if (args.length < 2) {
      printUsage();
      throw new IOException("Missing argument!");
    }
    int numberOfBytes = -1;
    try {
      numberOfBytes = Integer.parseInt(args[1]);
    } catch (Exception ex) {
      printUsage();
      throw new IOException("Incorrect argument!");
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

    // some token require login
    if (args.length > 4) {
      session.login(Session.UserType.USER, args[4].toCharArray());
    }

    System.out
        .println("################################################################################");
    System.out.print("generating " + numberOfBytes + " bytes of random data... ");

    byte[] dataBuffer = session.generateRandom(numberOfBytes);

    System.out.println("finished");
    System.out
        .println("################################################################################");

    OutputStream dataOutput;
    if (args.length > 2) {
      System.out
          .println("################################################################################");
      System.out.println("writing random data to file : " + args[2]);

      dataOutput = new FileOutputStream(args[2]);
    } else {
      System.out.println("random is:");
      dataOutput = System.out;
    }

    dataOutput.write(dataBuffer);
    dataOutput.flush();
    if (dataOutput instanceof FileOutputStream)
      dataOutput.close();
    System.out
        .println("################################################################################");

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    System.out
        .println("Usage: GenerateRandom <PKCS#11 module> <number of bytes> [<output file> <slot-index> <user-PIN> ]");
    System.out.println(" e.g.: GenerateRandom pk2priv.dll 128 random.dat");
    System.out.println("The given DLL must be in the search path of the system.");
  }

}
