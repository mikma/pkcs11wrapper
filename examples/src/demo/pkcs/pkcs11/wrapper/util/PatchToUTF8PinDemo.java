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

package demo.pkcs.pkcs11.wrapper.util;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

/**
 * This demo provides a method to change the encoding of the current PIN from ASCII to UTF8 (which
 * is now used per default). At first the demo logs in with the given PIN while UTF8 encoding is
 * disabled and changes the PIN to a dummy PIN (without special characters). Afterwards, UTF8
 * encoding is enabled again to change the dummy PIN to the given pin using UTF8 encoding.
 * 
 */
public class PatchToUTF8PinDemo {

  static PrintWriter output_;
  static BufferedReader input_;

  private String modulename_ = null;
  private static String pin_ = null;
  private int slotID_ = -1;
  private static Module pkcs11Module_ = null;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("demolog.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: PatchToUTF8PinDemo PKCS#11-module (USER|SO) [slot-index] [PIN]
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      printUsage();
    } else {
      try {
        boolean userType;
        if (args[1].equalsIgnoreCase("USER")) {
          userType = Session.UserType.USER;
        } else if (args[1].equalsIgnoreCase("SO")) {
          userType = Session.UserType.SO;
        } else {
          output_.println("Unknown user type: " + args[1]);
          printUsage();
          return;
        }
        input_ = new BufferedReader(new InputStreamReader(System.in));
        PatchToUTF8PinDemo demo = new PatchToUTF8PinDemo();
        demo.setTokenDetails(args);
        demo.patchPin(userType, pin_);
      } finally {
        pkcs11Module_.finalize(null);
        pkcs11Module_ = null;
      }
    }
  }

  private void setTokenDetails(String[] args) {
    if (args.length > 3) {
      modulename_ = args[0];
      slotID_ = Integer.parseInt(args[2]);
      pin_ = args[3];
    } else {
      if (args.length > 0)
        modulename_ = args[0];
      if (args.length > 2)
        slotID_ = Integer.parseInt(args[2]);
    }
  }

  private void patchPin(boolean isUserType, String pinArg) throws Exception {
    // get ascii provider for old pin
    Session session = getSession(false);
    TokenInfo tokenInfo = session.getToken().getTokenInfo();
    if (tokenInfo.isLoginRequired()) {
      String userTypeName = (isUserType == Session.UserType.USER) ? "user"
          : "security officer";
      System.out.print("Enter current " + userTypeName + " PIN: ");
      System.out.flush();
      String pinString;
      if (pinArg != null) {
        pinString = pinArg;
        System.out.println(pinString);
      } else {
        pinString = input_.readLine();
      }
      char[] pin = pinString.toCharArray();
      session.login(isUserType, pin);

      // convert pin to utf8 encoding
      byte[] encoding = pinString.getBytes("UTF8");
      String utf8String = new String(byteToCharArray(encoding));
      session.setPIN(pin, utf8String.toCharArray());
      session.closeSession();

      // test login with utf8 encoding
      session = getSession(true);
      session.login(isUserType, pin);
    } else {
      output_.println("This token does not require a login. It does not use a PIN.");
    }
    session.closeSession();

  }

  private char[] byteToCharArray(byte[] encoding) {
    char[] label = new char[encoding.length];
    for (int i = 0; i < encoding.length; i++) {
      label[i] = (char) (encoding[i] & 0xFF);
    }
    return label;
  }

  private Session getSession(boolean useUtf8Encoding) throws TokenException, IOException {
    if (pkcs11Module_ == null) {
      pkcs11Module_ = Module.getInstance(modulename_);
      pkcs11Module_.initialize(null);
    }

    Slot[] slots = pkcs11Module_.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

    if (slots.length == 0) {
      output_.println("No slot with present token found!");
      throw new TokenException("No token found!");
    }

    Slot selectedSlot;
    if (slotID_ >= 0) {
      if (slotID_ > slots.length - 1) {
        output_.println("Specified slot does not exist!");
        throw new TokenException("Specified slot does not exist!");
      }
      selectedSlot = slots[slotID_];
    } else
      // no slot id has been specified - therefore is -1 default value
      selectedSlot = slots[0];

    selectedSlot.setUtf8Encoding(useUtf8Encoding);

    Token token = selectedSlot.getToken();
    Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
        Token.SessionReadWriteBehavior.RW_SESSION, null, null);

    return session;
  }

  public static void printUsage() {
    output_
        .println("Usage: PatchToUTF8PinDemo <PKCS#11 module> (USER|SO) [<slot-index>] [<PIN>] ");
    output_.println(" e.g.: PatchToUTF8PinDemo cryptoki.dll User");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
