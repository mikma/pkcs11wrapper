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

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.SessionInfo;
import iaik.pkcs.pkcs11.State;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.BooleanAttribute;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Hashtable;

import demo.pkcs.pkcs11.wrapper.util.Util;

/**
 * This demo program allows to delete certain objects on a certain token. It allows the user to
 * select a token. Thereafter, it displays the objects on that token and lets the user select one of
 * them to delete it.
 */
public class DeleteObject {

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
   * usage: DeleteObject PKCS#11-module-name [slot-id] [pin] [auto]
   */
  public static void main(String[] args) throws TokenException, IOException {
    if (args.length < 1) {
      printUsage();
      throw new IOException("missing argument!");
    }

    Module pkcs11Module = Module.getInstance(args[0]);
    pkcs11Module.initialize(null);

    Token token;
    if (1 < args.length)
      token = Util.selectToken(pkcs11Module, output_, input_, args[1]);
    else
      token = Util.selectToken(pkcs11Module, output_, input_);
    if (token == null) {
      output_.println("We have no token to proceed. Finished.");
      output_.flush();
      throw new TokenException("No token found!");
    }

    Session session;
    if (2 < args.length)
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, args[2]);
    else
      session = Util.openAuthorizedSession(token,
          Token.SessionReadWriteBehavior.RW_SESSION, output_, input_, null);

    SessionInfo sessionInfo = session.getSessionInfo();
    output_.println("using session:");
    output_.println(sessionInfo);

    output_.println("listing all"
        + (((sessionInfo.getState() == State.RO_USER_FUNCTIONS) || (sessionInfo
            .getState() == State.RW_SO_FUNCTIONS)) ? "" : " public")
        + " objects on token with ID " + token.getTokenID());
    output_
        .println("________________________________________________________________________________");

    // limits the automatic deletion loop to one if argument "auto" is given
    boolean bot_state = true;

    deleteLoop: while (true) {
      session.findObjectsInit(null);
      Object[] objects = session.findObjects(1);
      Hashtable objectHandleToObject = new Hashtable(10);

      int limit = 0, counter = 0;
      if (3 < args.length)
        limit = 2;

      while (objects.length > 0 && (0 == limit || counter < limit)) {
        if (objects[0] instanceof Certificate || objects[0] instanceof Key) {
          if (objects[0] instanceof Certificate) {
            BooleanAttribute trusted = ((Certificate) objects[0]).getTrusted();
            if (trusted != null && trusted.getBooleanValue() != null
                && trusted.getBooleanValue().booleanValue()) { // trusted certificates might not be
                                                               // deletable
              objects = session.findObjects(1);
              continue;
            }
          }
          output_
              .println("--------------------------------------------------------------------------------");
          long objectHandle = objects[0].getObjectHandle();
          objectHandleToObject.put(new Long(objectHandle), objects[0]);
          output_.println("Object with handle: " + objectHandle);
          output_.println(objects[0]);
          output_
              .println("--------------------------------------------------------------------------------");
          counter++;
        }
        objects = session.findObjects(1);
      }
      session.findObjectsFinal();

      output_
          .println("________________________________________________________________________________");
      output_
          .println("################################################################################");

      Object selectedObject = null;
      Long selectedObjectHandle;
      if (objectHandleToObject.isEmpty()) {
        output_.println("There are no objects on the token.");
        break deleteLoop;
      } else {
        boolean gotObjectHandle = false;
        while (!gotObjectHandle) {
          output_.print("Enter the handle of the object to delete or 'x' to exit: ");
          output_.flush();
          String objectHandleString;
          if (3 < args.length) {
            if (bot_state) {
              objectHandleString = objectHandleToObject.keys().nextElement().toString();
              bot_state = false;
            } else {
              objectHandleString = "x";
            }
            output_.println(objectHandleString);
          } else {
            objectHandleString = input_.readLine();
          }
          if (objectHandleString.equalsIgnoreCase("x")) {
            break deleteLoop;
          }
          try {
            selectedObjectHandle = new Long(objectHandleString);
            selectedObject = (Object) objectHandleToObject.get(selectedObjectHandle);
            if (selectedObject != null) {
              gotObjectHandle = true;
            } else {
              output_.println("An object with the handle \"" + objectHandleString
                  + "\" does not exist. Try again.");
            }
          } catch (NumberFormatException ex) {
            output_.println("The entered handle \"" + objectHandleString
                + "\" is invalid. Try again.");
          }
        }
      }

      output_.println("Going to delete this object: ");
      output_.println(selectedObject);
      output_.println();
      output_
          .print("Are you sure that you want to DELETE this object permanently? [yes/no] ");
      output_.flush();
      String answer;
      if (3 < args.length) {
        answer = "yes";
        output_.println(answer);
      } else
        answer = input_.readLine();
      if (answer.equalsIgnoreCase("yes")) {
        session.destroyObject(selectedObject);
        output_.println("Object deleted.");
      }
    }
    session.closeSession();
    pkcs11Module.finalize(null);
  }

  protected static void printUsage() {
    output_.println("DeleteObject <PKCS#11 module name> [<slot-id>] [<pin>] [auto]");
    output_.println("e.g.: DeleteObject pk2priv.dll");
  }

}
