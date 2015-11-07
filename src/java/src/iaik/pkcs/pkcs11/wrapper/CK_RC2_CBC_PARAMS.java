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

/**
 * class CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC and CKM_RC2_CBC_PAD
 * mechanisms.
 * <p>
 * <B>PKCS#11 structure:</B>
 * 
 * <PRE>
 *  typedef struct CK_RC2_CBC_PARAMS {
 *    CK_ULONG ulEffectiveBits;
 *    CK_BYTE iv[8];
 *  } CK_RC2_CBC_PARAMS;
 * </PRE>
 * 
 * @author Karl Scheibelhofer
 * @author Martin Schläffer
 */
public class CK_RC2_CBC_PARAMS {

  /**
   * <B>PKCS#11:</B>
   * 
   * <PRE>
   * CK_ULONG ulEffectiveBits;
   * </PRE>
   */
  public long ulEffectiveBits; /* effective bits (1-1024) */

  /**
   * only the first 8 bytes will be used
   * <p>
   * <B>PKCS#11:</B>
   * 
   * <PRE>
   *   CK_BYTE iv[8];
   * </PRE>
   */
  public byte[] iv; /* IV for CBC mode */

  /**
   * Returns the string representation of CK_RC2_CBC_PARAMS.
   * 
   * @return the string representation of CK_RC2_CBC_PARAMS
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(Constants.INDENT);
    buffer.append("ulEffectiveBits: ");
    buffer.append(ulEffectiveBits);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("iv: ");
    buffer.append(Functions.toHexString(iv));
    // buffer.append(Constants.NEWLINE);

    return buffer.toString();
  }

}
