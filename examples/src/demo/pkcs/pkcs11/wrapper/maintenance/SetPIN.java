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
public class SetPIN {

  static PrintWriter output_;

  static BufferedReader input_;

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
   * Usage: SetPIN PKCS#11-module (USER|SO) [slot-index] [currentPin] [newPin]
   */
  public static void main(String[] args) throws TokenException, IOException {
    if (args.length < 2) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    try {
      boolean useUtf8Encoding = ((args.length > 5) ? Boolean.getBoolean(args[5]) : true);

      Slot[] slots = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

      if (slots.length == 0) {
        output_.println("No slot with present token found!");
        throw new TokenException("No token found!");
      }

      Token token = null;
      Slot selectedSlot;
      if (slots.length == 1) {
        selectedSlot = slots[0];
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
        if (2 < args.length) {
          selectedTokenNumberString = args[2];
          output_.print(args[2] + "\n");
        } else
          selectedTokenNumberString = input_.readLine();
        int selectedTokenNumber = Integer.parseInt(selectedTokenNumberString);
        selectedSlot = slots[selectedTokenNumber];
      }
      selectedSlot.setUtf8Encoding(useUtf8Encoding);
      token = selectedSlot.getToken();

      TokenInfo tokenInfo = token.getTokenInfo();

      output_
          .println("################################################################################");
      output_.println("Information of selsected Token:");
      output_.println(tokenInfo);
      output_
          .println("################################################################################");

      boolean userType = Session.UserType.USER;
      if (args[1].equalsIgnoreCase("USER")) {
        userType = Session.UserType.USER;
      } else if (args[1].equalsIgnoreCase("SO")) {
        userType = Session.UserType.SO;
      } else {
        output_.println("Unknown user type: " + args[1]);
        printUsage();
        pkcs11Module.finalize(null);
        throw new IOException("Unknown user type!");
      }
      String userTypeName = (userType == Session.UserType.USER) ? "user"
          : "security officer";

      output_
          .println("################################################################################");
      output_.println("setting " + userTypeName + " PIN");

      Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
          Token.SessionReadWriteBehavior.RW_SESSION, null, null);
      if (tokenInfo.isLoginRequired()) {
        if (tokenInfo.isProtectedAuthenticationPath()) {
          session.login(userType, null); // the token prompts the PIN by other means; e.g. PIN-pad
          session.setPIN(null, null);
        } else {
          output_.print("Enter current " + userTypeName + " PIN: ");
          output_.flush();
          String pinString;
          if (3 < args.length) {
            pinString = args[3];
            output_.print(args[3] + "\n");
          } else
            pinString = input_.readLine();
          char[] pin = pinString.toCharArray();
          // login user
          session.login(userType, pin);

          char[] newPIN = null;
          boolean repeat = false;
          do {
            output_.print("Enter new " + userTypeName + " PIN: ");
            output_.flush();
            String newPINString;
            if (4 < args.length) {
              newPINString = args[4];
              output_.print(args[4] + "\n");
            } else
              newPINString = input_.readLine();
            output_.print("Enter new " + userTypeName + " PIN again for confirmation: ");
            output_.flush();
            String confirmedNewPINString;
            if (4 < args.length) {
              confirmedNewPINString = args[4];
              output_.print(args[4] + "\n");
            } else
              confirmedNewPINString = input_.readLine();
            if (!newPINString.equals(confirmedNewPINString)) {
              output_.println("The two entries do not match. Try again.");
              repeat = true;
            } else {
              newPIN = newPINString.toCharArray();
              repeat = false;
            }
          } while (repeat);
          session.setPIN(pin, newPIN);
        }
      } else {
        output_.println("This token does not require a login. It does not use a PIN.");
      }

      output_.println("FINISHED");
      output_
          .println("################################################################################");
    } finally {
      pkcs11Module.finalize(null);
    }
  }

  public static void printUsage() {
    output_
        .println("Usage: SetPIN <PKCS#11 module> (USER|SO) [<slot-index>] [<currentPin>] [<newPin>]");
    output_.println(" e.g.: SetPIN pk2priv.dll USER");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
