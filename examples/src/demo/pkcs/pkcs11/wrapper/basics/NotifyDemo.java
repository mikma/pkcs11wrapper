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

package demo.pkcs.pkcs11.wrapper.basics;

import java.io.IOException;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Notify;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * This demo program tries to set a callback Notify handler.
 */
public class NotifyDemo implements Notify {

  /**
   * Usage: NotifyDemo PKCS#11-module [slot-index]
   */
  public static void main(String[] args) throws IOException, TokenException {
    if (args.length < 1) {
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
    if (1 < args.length)
      selectedSlot = slots[Integer.parseInt(args[1])];
    else
      selectedSlot = slots[0];
    Token token = selectedSlot.getToken();

    System.out
        .println("################################################################################");
    System.out.print("trying to set Notify callback handler... ");

    NotifyDemo callback = new NotifyDemo();
    String applicationData = "Hello Application!";
    Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
        Token.SessionReadWriteBehavior.RO_SESSION, applicationData, callback);

    System.out.println("finished");
    System.out
        .println("################################################################################");

    // FIXME, insert any code that causes a callback

    session.closeSession();
    pkcs11Module.finalize(null);
  }

  public static void printUsage() {
    System.out.println("Usage: NotifyDemo <PKCS#11 module> [<slot-index>]");
    System.out.println(" e.g.: NotifyDemo pk2priv.dll 0");
    System.out.println("The given DLL must be in the search path of the system.");
  }

  public void notify(Session session, boolean surrender, Object application)
      throws PKCS11Exception {
    System.out.println("we got a Notify callback !!!");
    // we do not throw an exception, this means return value CKR_OK
  }

}
