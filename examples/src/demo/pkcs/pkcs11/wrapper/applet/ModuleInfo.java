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

package demo.pkcs.pkcs11.wrapper.applet;

import java.applet.Applet;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Info;

/**
 * This demo program lists information about a module.
 */
public class ModuleInfo extends Applet {

  /**
   * auto-generated serial id
   */
  private static final long serialVersionUID = -8680181239066723664L;
  protected Module pkcs11Module_;

  /**
   * this allows us do an automated test of this demo
   */
  private String moduleName_;

  /**
   * this allows us do an automated test of this demo
   */
  public ModuleInfo(String moduleName) {
    this.moduleName_ = moduleName;
  }

  /**
   * Initialize this applet. Loads and initializes the module.
   */
  public void init() {
    String moduleName = moduleName_; // this allows us do an automated test of this demo
    if (null == moduleName) // this allows us do an automated test of this demo
      moduleName = getParameter("ModuleName");

    System.out.println("initializing module " + moduleName + " ... ");
    try {
      pkcs11Module_ = Module.getInstance(moduleName);
      pkcs11Module_.initialize(null);
    } catch (Throwable ex) {
      ex.printStackTrace();
    }
    System.out.println("...finished initializing");
  }

  /**
   * Start this applet. Gets info about the module and dumps it to the console.
   */
  public void start() {
    System.out.println("starting... ");

    try {
      System.out.print("getting module info...");
      Info info = pkcs11Module_.getInfo();
      System.out.println("finished");
      System.out.println("module info is:");
      System.out.println(info);
    } catch (Throwable ex) {
      ex.printStackTrace();
    }
    System.out.flush();
    System.err.flush();

    System.out.println("...finished starting");
  }

  /**
   * Stop this applet. Does effectively nothing.
   */
  public void stop() {
    System.out.print("stopping... ");
    System.out.println("finished");
  }

  /**
   * Destroy this applet. Finalizes the module.
   */
  public void destroy() {
    System.out.print("preparing for unloading...");
    try {
      pkcs11Module_.finalize(null);
      pkcs11Module_ = null;
    } catch (Throwable ex) {
      ex.printStackTrace();
    }
    System.out.println("finished");
  }

}
