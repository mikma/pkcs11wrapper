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
 * class CK_ATTRIBUTE includes the type, value and length of an attribute.
 * <p>
 * <B>PKCS#11 structure:</B>
 * 
 * <PRE>
 * typedef struct CK_ATTRIBUTE {&nbsp;&nbsp;
 *   CK_ATTRIBUTE_TYPE type;&nbsp;&nbsp;
 *   CK_VOID_PTR pValue;&nbsp;&nbsp;
 *   CK_ULONG ulValueLen;
 * } CK_ATTRIBUTE;
 * </PRE>
 * 
 * @author Karl Scheibelhofer
 * @author Martin Schläffer
 */
public class CK_ATTRIBUTE implements Cloneable {

  /**
   * <B>PKCS#11:</B>
   * 
   * <PRE>
   * CK_ATTRIBUTE_TYPE type;
   * </PRE>
   */
  public long type;

  /**
   * <B>PKCS#11:</B>
   * 
   * <PRE>
   * CK_VOID_PTR pValue;
   * CK_ULONG ulValueLen;
   * </PRE>
   */
  public Object pValue;

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   */
  public Object clone() {
    CK_ATTRIBUTE clone;

    try {
      clone = (CK_ATTRIBUTE) super.clone();

      // if possible, make a deep clone
      if (clone.pValue instanceof byte[]) {
        clone.pValue = ((byte[]) this.pValue).clone();
      } else if (clone.pValue instanceof char[]) {
        clone.pValue = ((char[]) this.pValue).clone();
      } else if (clone.pValue instanceof CK_DATE) {
        clone.pValue = ((CK_DATE) this.pValue).clone();
      } else if (clone.pValue instanceof boolean[]) {
        clone.pValue = ((boolean[]) this.pValue).clone();
      } else if (clone.pValue instanceof int[]) {
        clone.pValue = ((int[]) this.pValue).clone();
      } else if (clone.pValue instanceof long[]) {
        clone.pValue = ((long[]) this.pValue).clone();
      } else if (clone.pValue instanceof Object[]) {
        clone.pValue = ((Object[]) this.pValue).clone();
      } else {
        // the other supported objecty types: Boolean, Long, Byte, ... are immutable, no clone
        // needed
        clone.pValue = this.pValue;
      }
    } catch (CloneNotSupportedException ex) {
      // this must not happen, because this class is cloneable
      throw new PKCS11RuntimeException("An unexpected clone exception occurred.", ex);
    }

    return clone;
  }

  /**
   * Returns the string representation of CK_ATTRIBUTE.
   * 
   * @return the string representation of CK_ATTRIBUTE
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(Constants.INDENT);
    buffer.append("type: ");
    buffer.append(type);
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("pValue: ");
    buffer.append((pValue != null) ? pValue.toString() : "null");
    // buffer.append(Constants.NEWLINE);

    return buffer.toString();
  }

}
