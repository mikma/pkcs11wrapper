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
 * class CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism.<p>
 * <B>PKCS#11 structure:</B>
 * <PRE>
 * typedef struct CK_SKIPJACK_RELAYX_PARAMS {
 *   CK_ULONG ulOldWrappedXLen;
 *   CK_BYTE_PTR pOldWrappedX;
 *   CK_ULONG ulOldPasswordLen;
 *   CK_BYTE_PTR pOldPassword;
 *   CK_ULONG ulOldPublicDataLen;
 *   CK_BYTE_PTR pOldPublicData;
 *   CK_ULONG ulOldRandomLen;
 *   CK_BYTE_PTR pOldRandomA;
 *   CK_ULONG ulNewPasswordLen;
 *   CK_BYTE_PTR pNewPassword;
 *   CK_ULONG ulNewPublicDataLen;
 *   CK_BYTE_PTR pNewPublicData;
 *   CK_ULONG ulNewRandomLen;
 *   CK_BYTE_PTR pNewRandomA;
 * } CK_SKIPJACK_RELAYX_PARAMS;
 * </PRE>
 *
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 * @author Martin Schläffer <schlaeff@sbox.tugraz.at>
 */
public class CK_SKIPJACK_RELAYX_PARAMS {

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *   CK_BYTE_PTR pOldWrappedX;
	 *   CK_ULONG ulOldWrappedXLen;
	 * </PRE>
	 */
	public byte[] pOldWrappedX;

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *
	 *
	 * </PRE>
	 */
	public byte[] pOldPassword;

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *   CK_BYTE_PTR pOldPublicData;
	 *   CK_ULONG ulOldPublicDataLen;
	 * </PRE>
	 */
	public byte[] pOldPublicData;

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *   CK_BYTE_PTR pOldRandomA;
	 *   CK_ULONG ulOldRandomLen;
	 * </PRE>
	 */
	public byte[] pOldRandomA;

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *   CK_BYTE_PTR pNewPassword;
	 *   CK_ULONG ulNewPasswordLen;
	 * </PRE>
	 */
	public byte[] pNewPassword;

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *   CK_BYTE_PTR pNewPublicData;
	 *   CK_ULONG ulNewPublicDataLen;
	 * </PRE>
	 */
	public byte[] pNewPublicData;

	/**
	 * <B>PKCS#11:</B>
	 * <PRE>
	 *   CK_BYTE_PTR pNewRandomA;
	 *   CK_ULONG ulNewRandomLen;
	 * </PRE>
	 */
	public byte[] pNewRandomA;

	/**
	 * Returns the string representation of CK_SKIPJACK_RELAYX_PARAMS.
	 *
	 * @return the string representation of CK_SKIPJACK_RELAYX_PARAMS
	 */
	public String toString() {
		StringBuffer buffer = new StringBuffer();

		buffer.append(Constants.INDENT);
		buffer.append("ulOldWrappedXLen: ");
		buffer.append(pOldWrappedX.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pOldWrappedX: ");
		buffer.append(Functions.toHexString(pOldWrappedX));
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("ulOldPasswordLen: ");
		buffer.append(pOldPassword.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pOldPassword: ");
		buffer.append(Functions.toHexString(pOldPassword));
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("ulOldPublicDataLen: ");
		buffer.append(pOldPublicData.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pOldPublicData: ");
		buffer.append(Functions.toHexString(pOldPublicData));
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("ulOldRandomLen: ");
		buffer.append(pOldRandomA.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pOldRandomA: ");
		buffer.append(Functions.toHexString(pOldRandomA));
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("ulNewPasswordLen: ");
		buffer.append(pNewPassword.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pNewPassword: ");
		buffer.append(Functions.toHexString(pNewPassword));
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("ulNewPublicDataLen: ");
		buffer.append(pNewPublicData.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pNewPublicData: ");
		buffer.append(Functions.toHexString(pNewPublicData));
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("ulNewRandomLen: ");
		buffer.append(pNewRandomA.length);
		buffer.append(Constants.NEWLINE);

		buffer.append(Constants.INDENT);
		buffer.append("pNewRandomA: ");
		buffer.append(Functions.toHexString(pNewRandomA));
		//buffer.append(Constants.NEWLINE);

		return buffer.toString();
	}

}
