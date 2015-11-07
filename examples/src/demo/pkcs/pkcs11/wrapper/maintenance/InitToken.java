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

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.TokenInfo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import demo.pkcs.pkcs11.wrapper.util.Util;

/**
 * This program initializes a token. Note that this erases all data on the token.
 */
public class InitToken {

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
   * Usage: InitToken PKCS#11-module Card-Label [slot-id] [SO Pin] [User Pin]
   */
  public static void main(String[] args) throws TokenException, IOException {
    if (args.length < 2) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    try {
      Token token;
      if (2 < args.length)
        token = Util.selectToken(pkcs11Module, output_, input_, args[2]);
      else
        token = Util.selectToken(pkcs11Module, output_, input_, null);

      if (token == null) {
        output_.println("We have no token to proceed. Finished.");
        output_.flush();
        throw new TokenException("No token found!");
      }

      TokenInfo tokenInfo = token.getTokenInfo();

      output_
          .println("################################################################################");
      output_.println("Information of Token to be initialized:");
      output_.println(tokenInfo);
      output_
          .println("################################################################################");

      /*
       * output_.println(
       * "################################################################################");
       * output_.println(
       * "ATTENTION! Initialization will start in 10 seconds. You have time to remove the token or press any key to abort. Countdown... "
       * );
       * 
       * InputStreamReader inputReader = new InputStreamReader(System.in); for (int i = 10; i >= 0;
       * i--) { output_.print("\r"); output_.print(i); output_.print(' '); output_.flush();
       * Thread.sleep(1000); if (inputReader.ready()) { output_.println("Aborted...EXIT");
       * output_.flush(); pkcs11Module.finalize(null); } } output_.println();
       */
      output_.print("initializing... ");

      String soPINString = null;
      if (tokenInfo.isProtectedAuthenticationPath()) {
        output_.print("Please enter the SO-PIN at the PIN-pad of your reader.");
        token.initToken(null, args[1]);
        ; // the token prompts the PIN by other means; e.g. PIN-pad
      } else {
        output_.print("Enter the SO-PIN and press [return key]: ");
        output_.flush();
        if (3 < args.length) {
          soPINString = args[3];
          output_.print(args[3] + "\n");
        } else
          soPINString = input_.readLine();
        token.initToken(soPINString.toCharArray(), args[1]);
      }
      output_.println("FINISHED");

      // login security officer
      // if (tokenInfo.isLoginRequired()) {
      output_.print("initializing user-PIN... ");
      Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
          Token.SessionReadWriteBehavior.RW_SESSION, null, null);

      if (tokenInfo.isProtectedAuthenticationPath()) {
        output_.print("Please enter the SO-PIN at the PIN-pad of your reader.");
        output_.flush();
        session.login(Session.UserType.SO, null); // the token prompts the PIN by other means; e.g.
                                                  // PIN-pad
        output_.print("Please enter the user-PIN at the PIN-pad of your reader.");
        output_.flush();
        session.initPIN(null);
      } else {
        if (soPINString != null) {
          session.login(Session.UserType.SO, soPINString.toCharArray());
        } else {
          output_.print("Enter the SO-PIN and press [return key]: ");
          output_.flush();
          if (3 < args.length) {
            soPINString = args[3];
            output_.print(args[3] + "\n");
          } else
            soPINString = input_.readLine();
          session.login(Session.UserType.SO, soPINString.toCharArray());
        }
        output_.print("Enter the user-PIN and press [return key]: ");
        output_.flush();
        String userPINString;
        if (4 < args.length) {
          userPINString = args[4];
          output_.print(args[4] + "\n");
        } else
          userPINString = input_.readLine();
        session.initPIN(userPINString.toCharArray());
      }
      session.closeSession();
      output_.println("FINISHED");
      // }

      output_
          .println("################################################################################");

      tokenInfo = token.getTokenInfo();

      output_
          .println("################################################################################");
      output_.println("Information of initialized Token:");
      output_.println(tokenInfo);
      output_
          .println("################################################################################");

    } finally {
      pkcs11Module.finalize(null);
    }
  }

  public static void printUsage() {
    output_
        .println("Usage: InitToken <PKCS#11 module> \"Card Label\" [<slot-id>] [<SO Pin>] [<User Pin>]");
    output_.println(" e.g.: InitToken pk2priv.dll \"My Test Card\"");
    output_.println("ATTENTION: Any data on the card will get lost upon initialization!");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
