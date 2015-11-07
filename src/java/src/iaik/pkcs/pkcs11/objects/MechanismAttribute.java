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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * Objects of this class represent a mechanism attribute of an PKCS#11 object as specified by
 * PKCS#11.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (ckAttribute_ <> null)
 */
public class MechanismAttribute extends LongAttribute {

  /**
   * Default constructor - only for internal use in AttributeArrayAttribute.getValueString().
   */
  MechanismAttribute() {
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
  public MechanismAttribute(Long type) {
    super(type);
  }

  /**
   * Set the mechanism value of this attribute. <code>null</code>, is also valid. A call to this
   * method sets the present flag to true.
   * 
   * @param mechanism
   *          The mechanism value to set. May be <code>null</code>.
   */
  public void setMechanism(Mechanism mechanism) {
    ckAttribute_.pValue = (mechanism != null) ? new Long(mechanism.getMechanismCode())
        : null;
    present_ = true;
  }

  /**
   * Get the long value of this attribute. Null, is also possible.
   * 
   * @return The long value of this attribute or null.
   */
  public Mechanism getMechanism() {
    return ((ckAttribute_ != null) && (ckAttribute_.pValue != null)) ? new Mechanism(
        ((Long) ckAttribute_.pValue).longValue()) : null;
  }

  /**
   * Get a string representation of the value of this attribute.
   * 
   * @return A string representation of the value of this attribute.
   * 
   * @postconditions (result <> null)
   */
  protected String getValueString() {
    String valueString;

    if ((ckAttribute_ != null) && (ckAttribute_.pValue != null)) {
      if (((Long) ckAttribute_.pValue).longValue() != PKCS11Constants.CK_UNAVAILABLE_INFORMATION) {
        valueString = Functions.mechanismCodeToString(((Long) ckAttribute_.pValue)
            .longValue());
      } else {
        valueString = "<Information unavailable>";
      }
    } else {
      valueString = "<NULL_PTR>";
    }

    return valueString;
  }

}
