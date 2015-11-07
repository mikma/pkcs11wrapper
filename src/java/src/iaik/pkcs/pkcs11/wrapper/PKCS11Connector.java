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

package iaik.pkcs.pkcs11.wrapper;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

/**
 * This class is a sort of factory to get a implementation of the PKCS11 interface. By now, this
 * method simply instanciates PKCS11Implementation. For future version, it can be extended to
 * support different implementations for different versions of PKCS#11.
 * 
 * @author Karl Scheibelhofer
 * @author Martin Schläffer
 */
public class PKCS11Connector {

  /**
   * directory including natives in jar file
   */
  private static final String WRAPPER_BASE_PATH = "natives/";

  /**
   * index constants per OS as used in below arrays
   */
  private static final int LINUX_INDEX = 0;
  private static final int WIN_INDEX = 1;
  private static final int MAC_INDEX = 2;
  private static final int SOLARIS_INDEX = 3;
  /**
   * subdirectories per OS
   */
  private static final String[] WRAPPER_OS_PATH = { "unix/linux-", "windows/win-",
      "unix/macosx_universal/", "unix/solaris_" };
  /**
   * file suffix per OS
   */
  private static final String[] WRAPPER_FILE_SUFFIX = { ".so", ".dll", ".jnilib", ".so" };
  /**
   * file prefix per OS
   */
  private static final String[] WRAPPER_FILE_PREFIX = { "lib", "", "lib", "lib" };
  /**
   * index constants per architecture as used in below array
   */
  private static final int X64_INDEX = 0;
  private static final int X86_INDEX = 1;
  private static final int SPARC_INDEX = 2;
  /**
   * subdirectories per architecture
   */
  private static final String[] WRAPPER_ARCH_PATH = { "x86_64/", "x86/", "sparcv9/" };
  /**
   * subdirectory for release version as included in each architecture directory
   */
  private static final String RELEASE_DIR = "release/";
  /**
   * subdirectory for debug version as included in each architecture directory
   */
  private static final String DEBUG_DIR = "debug/";

  /**
   * Empty constructor for internal use only.
   * 
   */
  protected PKCS11Connector() { /* left empty intentionally */
  }

  /**
   * Connect to a PKCS#11 module and get an interface to it. Tries to load the PKCS#11 wrapper
   * native library from the library path or the class path (jar file).
   * 
   * @param pkcs11ModulePath
   *          The path to the PKCS#11 library.
   * @return The interface object to access the PKCS#11 module.
   * @exception IOException
   *              If finding the module or connecting to it fails.
   */
  public static PKCS11 connectToPKCS11Module(String pkcs11ModulePath) throws IOException {
    return new PKCS11Implementation(pkcs11ModulePath);
  }

  /**
   * Connect to a PKCS#11 module and get an interface to it. Tries to load the PKCS#11 wrapper
   * native library from the library path or the class path (jar file). If loaded from the jar file,
   * uses the debug version if wrapperDebugVersion is true.
   * 
   * @param pkcs11ModulePath
   *          The path to the PKCS#11 library.
   * @param wrapperDebugVersion
   *          true, if the PKCS#11 wrapper library's debug version shall be loaded
   * @return The interface object to access the PKCS#11 module.
   * @exception IOException
   *              If finding the module or connecting to it fails.
   */
  public static PKCS11 connectToPKCS11Module(String pkcs11ModulePath,
      boolean wrapperDebugVersion) throws IOException {
    return new PKCS11Implementation(pkcs11ModulePath, wrapperDebugVersion);
  }

  /**
   * Connect to a PKCS#11 module with the specified PKCS#11-wrapper native library and get an
   * interface to it.
   * 
   * @param pkcs11ModulePath
   *          The path to the PKCS#11 library.
   * @param pkcs11WrapperPath
   *          The absolute path to the PKCS#11-wrapper native library including the filename
   * @return The interface object to access the PKCS#11 module.
   * @exception IOException
   *              If finding the module or connecting to it fails.
   */
  public static PKCS11 connectToPKCS11Module(String pkcs11ModulePath,
      String pkcs11WrapperPath) throws IOException {
    return new PKCS11Implementation(pkcs11ModulePath, pkcs11WrapperPath);
  }

  /**
   * Tries to load the PKCS#11 wrapper native library included in the class path (jar file). If
   * loaded from the jar file and wrapperDebugVersion is true, uses the included debug version. The
   * found native library is copied to the temporary-file directory and loaded from there.
   * 
   * @param wrapperDebugVersion
   *          true, if the PKCS#11 wrapper library's debug version shall be loaded
   * @throws IOException
   *           if the wrapper native library for the system's architecture can't be found in the jar
   *           file or if corresponding native library can't be written to temporary directory
   */
  public static void loadWrapperFromJar(boolean wrapperDebugVersion) throws IOException {

    String libName;
    String osFileEnding;
    String jarFilePath;

    String system;
    String architecture;
    String debug;
    boolean success = false;
    boolean tryAgain = false;
    int trialCounter = 0;

    String osName = System.getProperty("os.name");
    int osIndex = getOS(osName);
    String archName = System.getProperty("os.arch");
    int archIndex = getArch(archName);
    if (osIndex == -1) {
      osIndex = 0; // it may be some Linux - try it
    }
    if (archIndex == -1) {
      archIndex = 0;
      trialCounter++;
    }

    system = WRAPPER_BASE_PATH + WRAPPER_OS_PATH[osIndex];
    if (osIndex == MAC_INDEX) {
      architecture = "";
      // no other choice than universal
    } else {
      architecture = WRAPPER_ARCH_PATH[archIndex];
    }
    if (wrapperDebugVersion) {
      debug = DEBUG_DIR;
    } else {
      debug = RELEASE_DIR;
    }

    libName = WRAPPER_FILE_PREFIX[osIndex] + PKCS11Implementation.PKCS11_WRAPPER;
    osFileEnding = WRAPPER_FILE_SUFFIX[osIndex];

    do {
      tryAgain = false;
      jarFilePath = system + architecture + debug;
      File tempWrapperFile = null;
      InputStream wrapperLibrary = PKCS11Connector.class.getClassLoader()
          .getResourceAsStream(jarFilePath + libName + osFileEnding);
      if (wrapperLibrary == null) {
        if (trialCounter < WRAPPER_ARCH_PATH.length) {
          archIndex = trialCounter++;
          architecture = WRAPPER_ARCH_PATH[archIndex];
          tryAgain = true;
          continue;
        } else {
          throw new IOException("No suitable wrapper native library for " + osName + " "
              + archName + " found in jar file.");
        }
      }
      try {
        tempWrapperFile = File.createTempFile(libName, osFileEnding);
        if (!tempWrapperFile.canWrite()) {
          throw new IOException(
              "Can't copy wrapper native library to local temporary directory.");
        }
        tempWrapperFile.deleteOnExit();

        FileOutputStream os = new FileOutputStream(tempWrapperFile);
        try {
          int read = 0;
          byte[] buffer = new byte[1024];
          while ((read = wrapperLibrary.read(buffer)) > -1) {
            os.write(buffer, 0, read);
          }
        } finally {
          os.close();
          wrapperLibrary.close();
        }
      } catch (IOException e) {
        // error writing found library, other architecture would not change this
        if (tempWrapperFile != null)
          tempWrapperFile.delete();
        throw new IOException(
            "Can't copy wrapper native library to local temporary directory.");
      } catch (RuntimeException e) {
        if (tempWrapperFile != null)
          tempWrapperFile.delete();
        throw e;
      }

      try {
        System.load(tempWrapperFile.getAbsolutePath());
        success = true;
      } catch (UnsatisfiedLinkError e) {
        if (tempWrapperFile != null)
          tempWrapperFile.delete();
        if (trialCounter < WRAPPER_ARCH_PATH.length) {
          archIndex = trialCounter++;
          architecture = WRAPPER_ARCH_PATH[archIndex];
          tryAgain = true;
        } else {
          throw new IOException("No suitable wrapper native library found in jar file. "
              + osName + " " + archName + " not supported.");
        }
      }
    } while (!success && tryAgain);

  }

  /**
   * Returns the index in the WRAPPER_OS_PATH array corresponding to the given OS name.
   * 
   * @param osName
   *          name of the used operating system
   * @return index to be used with WRAPPER_OS_PATH
   */
  private static int getOS(String osName) {
    if (osName.toLowerCase().indexOf("win") > -1) {
      return WIN_INDEX;
    } else if (osName.toLowerCase().indexOf("linux") > -1) {
      return LINUX_INDEX;
    } else if (osName.toLowerCase().indexOf("mac") > -1) {
      return MAC_INDEX;
    } else if (osName.toLowerCase().indexOf("sun") > -1) {
      return SOLARIS_INDEX;
    } else
      return -1;
  }

  /**
   * Returns the index in the WRAPPER_ARCH_PATH array corresponding to the given architecture.
   * 
   * @param jvmArch
   *          currently used architecture
   * @return index to be used with WRAPPER_ARCH_PATH
   */
  private static int getArch(String jvmArch) {
    if (jvmArch.indexOf("64") > -1)
      return X64_INDEX;
    else if (jvmArch.indexOf("sparc") > -1)
      return SPARC_INDEX;
    else if (jvmArch.indexOf("32") > -1 || jvmArch.indexOf("86") > -1)
      return X86_INDEX;
    else
      return -1;
  }

}
