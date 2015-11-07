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

package demo.pkcs.pkcs11.wrapper.maintenance;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;

/**
 * This program sets the normal user's PIN.
 */
public class InitPIN {

  static PrintWriter output_;

  static BufferedReader input_;

  static {
    try {
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: InitPIN PKCS#11-module SO-PIN user-PIN [slot-index]
   */
  public static void main(String[] args) throws IOException, TokenException {
    if (args.length < 3) {
      printUsage();
      throw new IOException("Missing argument!");
    }
    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    try {
      Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

      if (slots.length == 0) {
        output_.println("No slot with present token found!");
        throw new TokenException("No token found!");
      }

      Token token = null;
      if (slots.length == 1) {
        Slot selectedSlot = slots[0];
        token = selectedSlot.getToken();
      } else {
        output_.println("Found several tokens: ");
        for (int i = 0; i < slots.length; i++) {
          token = slots[i].getToken();
          output_
              .println("________________________________________________________________________________");
          output_.print("Info of Token number ");
          output_.println(i);
          output_.println(token.getTokenInfo());
          output_
              .println("________________________________________________________________________________");
        }
        output_.println();
        output_
            .print("For which token do you want to set the PIN? Please enter its number [0..");
        output_.print(slots.length);
        output_.print("]: ");
        output_.flush();
        String selectedTokenNumberString;
        if (args.length == 4) {
          selectedTokenNumberString = args[3];
          output_.print(args[3]);
        } else
          selectedTokenNumberString = input_.readLine();

        int selectedTokenNumber = Integer.parseInt(selectedTokenNumberString);
        token = slots[selectedTokenNumber].getToken();
      }

      TokenInfo tokenInfo = token.getTokenInfo();

      output_
          .println("\n################################################################################");
      output_.println("Information of selsected Token:");
      output_.println(tokenInfo);
      output_
          .println("################################################################################");

      output_
          .println("################################################################################");
      output_.print("initializing user-PIN... ");
      Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
          Token.SessionReadWriteBehavior.RW_SESSION, null, null);
      // login security officer
      session.login(Session.UserType.SO, args[1].toCharArray());
      session.initPIN(args[2].toCharArray());
      output_.println("FINISHED");

      output_
          .println("################################################################################");

    } finally {
      pkcs11Module.finalize(null);
    }
  }

  public static void printUsage() {
    output_.println("Usage: InitPIN <PKCS#11 module> <SO-PIN> <user-PIN> [<slot-index>]");
    output_.println(" e.g.: InitPIN pk2priv.dll 12345678 1234");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
