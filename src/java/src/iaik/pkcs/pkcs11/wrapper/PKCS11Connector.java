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

import java.io.IOException;

/**
 * This class is a sort of factory to get a implementation of the PKCS11
 * interface. By now, this method simply instanciates PKCS11Implementation.
 * For future version, it can be extended to support different implementations
 * for different versions of PKCS#11.
 *
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 * @author Martin Schläffer <schlaeff@sbox.tugraz.at>
 */
public class PKCS11Connector {

	/**
	 * Empty constructor for internal use only.
	 *
	 * @preconditions
	 * @postconditions
	 */
	protected PKCS11Connector() { /* left empty intentionally */
	}

	/**
	 * Connect to a PKCS#11 module and get an interface to it.
	 *
	 * @param pkcs11ModulePath The path to the PKCS#11 library.
	 * @return The interface object to access the PKCS#11 module.
	 * @exception IOException If finding the module or connecting to it fails.
	 */
	public static PKCS11 connectToPKCS11Module(String pkcs11ModulePath)
	    throws IOException
	{
		return new PKCS11Implementation(pkcs11ModulePath);
	}

	/**
	 * Connect to a PKCS#11 module with the specified PKCS#11-wrapper native library and get an interface to it.
	 *
	 * @param pkcs11ModulePath The path to the PKCS#11 library.
	 * @param pkcs11WrapperPath The absolute path to the PKCS#11-wrapper native library including the filename
	 * @return The interface object to access the PKCS#11 module.
	 * @exception IOException If finding the module or connecting to it fails.
	 */
	public static PKCS11 connectToPKCS11Module(String pkcs11ModulePath,
	                                           String pkcs11WrapperPath)
	    throws IOException
	{
		return new PKCS11Implementation(pkcs11ModulePath, pkcs11WrapperPath);
	}

}
