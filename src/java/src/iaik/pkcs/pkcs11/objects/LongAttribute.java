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

package iaik.pkcs.pkcs11.objects;

/**
 * Objects of this class represent a long attribute of an PKCS#11 object as specified by PKCS#11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class LongAttribute extends Attribute {

  /**
   * Default constructor - only for internal use in AttributeArrayAttribute.getValueString().
   */
  LongAttribute() {
    super();
  }

  /**
   * Constructor taking the PKCS#11 type of the attribute.
   * 
   * @param type
   *          The PKCS'11 type of this attribute; e.g. PKCS11Constants.CKA_VALUE_LEN.
   * @preconditions (type <> null)
   * 
   */
  public LongAttribute(Long type) {
    super(type);
  }

  /**
   * Set the long value of this attribute. Null, is also valid. A call to this method sets the
   * present flag to true.
   * 
   * @param value
   *          The long value to set. May be null.
   */
  public void setLongValue(Long value) {
    ckAttribute_.pValue = value;
    present_ = true;
  }

  /**
   * Get the long value of this attribute. Null, is also possible.
   * 
   * @return The long value of this attribute or null.
   */
  public Long getLongValue() {
    return (Long) ckAttribute_.pValue;
  }

  /**
   * Get a string representation of the value of this attribute. The radix for the presentation can
   * be specified; e.g. 16 for hex, 10 for decimal.
   * 
   * @param radix
   *          The radix for the representation of the value.
   * @return A string representation of the value of this attribute.
   * 
   * @postconditions (result <> null)
   */
  protected String getValueString(int radix) {
    String valueString;

    if ((ckAttribute_ != null) && (ckAttribute_.pValue != null)) {
      valueString = Long.toString(((Long) ckAttribute_.pValue).longValue(), radix);
    } else {
      valueString = "<NULL_PTR>";
    }

    return valueString;
  }

  /**
   * Get a string representation of this attribute. The radix for the presentation of the value can
   * be specified; e.g. 16 for hex, 10 for decimal.
   * 
   * @param radix
   *          The radix for the representation of the value.
   * @return A string representation of the value of this attribute.
   * 
   * @postconditions (result <> null)
   */
  public String toString(int radix) {
    StringBuffer buffer = new StringBuffer(32);

    if (present_) {
      if (sensitive_) {
        buffer.append("<Value is sensitive>");
      } else {
        buffer.append(getValueString(radix));
      }
    } else {
      buffer.append("<Attribute not present>");
    }

    return buffer.toString();
  }

  /*
   * (non-Javadoc)
   * 
   * @see iaik.pkcs.pkcs11.objects.Attribute#setValue(java.lang.Object)
   */
  public void setValue(java.lang.Object value) throws UnsupportedOperationException {
    setLongValue((Long) value);
  }

}
