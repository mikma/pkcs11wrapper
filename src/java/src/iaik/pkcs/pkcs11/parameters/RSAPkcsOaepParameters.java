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

package iaik.pkcs.pkcs11.parameters;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.wrapper.CK_RSA_PKCS_OAEP_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * This class encapsulates parameters for the Mechanism.RSA_PKCS_OAEP.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (source_ == SourceType.Empty) or (source_ == SourceType.DataSpecified)
 */
public class RSAPkcsOaepParameters extends RSAPkcsParameters {

  /**
   * This interface defines the available source types as defined by PKCS#11: CKZ_DATA_SPECIFIED.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface SourceType {

    /**
     * The indentifier for empty parameter. This is not defined explicitely in the PKCS#11 v2.11
     * standard but in the text.
     */
    static public final long EMPTY = 0L;

    /**
     * The indentifier for CKZ_DATA_SPECIFIED.
     */
    static public final long DATA_SPECIFIED = PKCS11Constants.CKZ_DATA_SPECIFIED;

  }

  /**
   * The source of the encoding parameter.
   */
  protected long source_;

  /**
   * The data used as the input for the encoding parameter source.
   */
  protected byte[] sourceData_;

  /**
   * Create a new RSAPkcsOaepParameters object with the given attributes.
   * 
   * @param hashAlgorithm
   *          The message digest algorithm used to calculate the digest of the encoding parameter.
   * @param maskGenerationFunction
   *          The mask to apply to the encoded block. One of the constants defined in the
   *          MessageGenerationFunctionType interface.
   * @param source
   *          The source of the encoding parameter. One of the constants defined in the SourceType
   *          interface.
   * @param sourceData
   *          The data used as the input for the encoding parameter source.
   * @preconditions (hashAlgorithm <> null) and (maskGenerationFunction ==
   *                MessageGenerationFunctionType.Sha1) and ((source == SourceType.Empty) or (source
   *                == SourceType.DataSpecified))
   * 
   */
  public RSAPkcsOaepParameters(Mechanism hashAlgorithm, long maskGenerationFunction,
      long source, byte[] sourceData) {
    super(hashAlgorithm, maskGenerationFunction);
    if ((source != SourceType.EMPTY) && (source != SourceType.DATA_SPECIFIED)) {
      throw new IllegalArgumentException("Illegal value for argument\"source\": "
          + Functions.toHexString(source));
    }
    source_ = source;
    sourceData_ = sourceData;
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   * 
   * @postconditions (result <> null) and (result instanceof RSAPkcsOaepParameters) and
   *                 (result.equals(this))
   */
  public java.lang.Object clone() {
    RSAPkcsOaepParameters clone = (RSAPkcsOaepParameters) super.clone();

    clone.sourceData_ = (byte[]) this.sourceData_.clone();

    return clone;
  }

  /**
   * Get this parameters object as an object of the CK_RSA_PKCS_OAEP_PARAMS class.
   * 
   * @return This object as a CK_RSA_PKCS_OAEP_PARAMS object.
   * 
   * @postconditions (result <> null)
   */
  public Object getPKCS11ParamsObject() {
    CK_RSA_PKCS_OAEP_PARAMS params = new CK_RSA_PKCS_OAEP_PARAMS();

    params.hashAlg = hashAlgorithm_.getMechanismCode();
    params.mgf = maskGenerationFunction_;
    params.source = source_;
    params.pSourceData = sourceData_;

    return params;
  }

  /**
   * Get the source of the encoding parameter.
   * 
   * @return The source of the encoding parameter.
   */
  public long getSource() {
    return source_;
  }

  /**
   * Get the data used as the input for the encoding parameter source.
   * 
   * @return The data used as the input for the encoding parameter source.
   */
  public byte[] getSourceData() {
    return sourceData_;
  }

  /**
   * Set the source of the encoding parameter. One of the constants defined in the SourceType
   * interface.
   * 
   * @param source
   *          The source of the encoding parameter.
   * @preconditions ((source == SourceType.Empty) or (source == SourceType.DataSpecified))
   * 
   */
  public void setSource(long source) {
    if ((source != SourceType.EMPTY) && (source != SourceType.DATA_SPECIFIED)) {
      throw new IllegalArgumentException("Illegal value for argument\"source\": "
          + Functions.toHexString(source));
    }
    source_ = source;
  }

  /**
   * Set the data used as the input for the encoding parameter source.
   * 
   * @param sourceData
   *          The data used as the input for the encoding parameter source.
   */
  public void setSourceData(byte[] sourceData) {
    sourceData_ = sourceData;
  }

  /**
   * Returns the string representation of this object. Do not parse data from this string, it is for
   * debugging only.
   * 
   * @return A string representation of this object.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append(super.toString());
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Source: ");
    if (source_ == SourceType.EMPTY) {
      buffer.append("Empty");
    } else if (source_ == SourceType.DATA_SPECIFIED) {
      buffer.append("Data Specified");
    } else {
      buffer.append("<unknown>");
    }
    buffer.append(Constants.NEWLINE);

    buffer.append(Constants.INDENT);
    buffer.append("Source Data (hex): ");
    buffer.append(Functions.toHexString(sourceData_));
    // buffer.append(Constants.NEWLINE);

    return buffer.toString();
  }

  /**
   * Compares all member variables of this object with the other object. Returns only true, if all
   * are equal in both objects.
   * 
   * @param otherObject
   *          The other object to compare to.
   * @return True, if other is an instance of this class and all member variables of both objects
   *         are equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof RSAPkcsOaepParameters) {
      RSAPkcsOaepParameters other = (RSAPkcsOaepParameters) otherObject;
      equal = (this == other)
          || (super.equals(other) && (this.source_ == other.source_) && Functions.equals(
              this.sourceData_, other.sourceData_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return super.hashCode() ^ ((int) source_) ^ Functions.hashCode(sourceData_);
  }

}
