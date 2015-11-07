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

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

import iaik.pkcs.pkcs11.Info;
import iaik.pkcs.pkcs11.InitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.MutexHandler;
import iaik.pkcs.pkcs11.TokenException;

/**
 * This demo program tries to call initialize with some arguments.
 */
public class InitArgs implements InitializeArgs {

  static PrintWriter output_;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("GetInfo_output.txt"), true);
      output_ = new PrintWriter(System.out, true);
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
    }
  }

  public static void main(String[] args) throws TokenException, IOException {
    if ((args.length == 1) || (args.length == 2)) {
      output_
          .println("################################################################################");
      output_.println("load and initialize module \"" + args[0]
          + "\" using InitializeArgs");
      output_.flush();
      Module pkcs11Module = Module.getInstance(args[0]);
      byte[] reservedParameter = (args.length >= 2) ? readStream(new FileInputStream(
          args[1])) : null;
      InitializeArgs initArgs = new InitArgs(reservedParameter);
      pkcs11Module.initialize(initArgs);

      Info info = pkcs11Module.getInfo();
      output_.println(info);
      output_
          .println("################################################################################");
    } else {
      printUsage();
    }
    System.gc(); // to finalize and disconnect the pkcs11Module
  }

  protected static void printUsage() {
    output_
        .println("InitArgs <PKCS#11 module name> [<file providing reserved parameter>]");
    output_.println("e.g.: InitArgs slbck.dll");
  }

  /**
   * Read the contents of the stream into a byte array. The stream is read until it returns EOF.
   */
  protected static byte[] readStream(InputStream in) throws IOException {
    ByteArrayOutputStream bufferStream = new ByteArrayOutputStream(256); // initial size
    int bytesRead;
    byte[] buffer = new byte[256];
    while ((bytesRead = in.read(buffer)) >= 0) {
      bufferStream.write(buffer, 0, bytesRead);
    }
    return bufferStream.toByteArray();
  }

  protected byte[] reservedParameter_;

  public InitArgs(byte[] reservedParameter) {
    reservedParameter_ = reservedParameter;
  }

  /**
   * Get the handler object that handes mutex objects.
   * 
   * @return The mutex handler object or null, if there is none set.
   */
  public MutexHandler getMutexHandler() {
    output_.println("getMutexHandler() called");
    return null;
  }

  /**
   * Checks, if the library is not allowed to create operating system threads.
   * 
   * @return True, if the library is not allowed to create operating system threads; false,
   *         otherwise.
   */
  public boolean isLibraryCantCreateOsThreads() {
    output_.println("isLibraryCantCreateOsThreads() called");
    return false;
  }

  /**
   * Checks, if the library is allowed to use locking mechanisms of the operating system.
   * 
   * @return True, if the library is allowed to use locking mechanisms of the operating system.
   */
  public boolean isOsLockingOk() {
    output_.println("isOsLockingOk() called");
    return true;
  }

  /**
   * Get the reserved parameter. This is always null as of version 2.11 of PKCS#11.
   * 
   * @return null as of version 2.11 of PKCS#11.
   * 
   * @postconditions (result == null)
   */
  public java.lang.Object getReserved() {
    output_.println("getReserved() called");
    return reservedParameter_;
  }

}
