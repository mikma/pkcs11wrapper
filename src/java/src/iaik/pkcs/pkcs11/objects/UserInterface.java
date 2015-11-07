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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.Constants;

import java.io.UnsupportedEncodingException;

/**
 * Objects of this class represent a user interface as specified by PKCS#11 v2.20.
 * 
 * @author Florian Reimair
 * @version 1.0
 */
public class UserInterface extends HardwareFeature {

  private LongAttribute pixelX_;
  private LongAttribute pixelY_;
  private LongAttribute resolution_;
  private LongAttribute charRows_;
  private LongAttribute charColumns_;
  private BooleanAttribute color_;
  private LongAttribute bitsPerPixel_;
  private ByteArrayAttribute charSets_;
  private ByteArrayAttribute encodingMethods_;
  private ByteArrayAttribute mimeTypes_;

  /**
   * Deafult Constructor.
   */
  public UserInterface() {
    super();
    hardwareFeatureType_.setLongValue(FeatureType.USER_INTERFACE);
  }

  /**
   * Called by getInstance to create an instance of a PKCS#11 user interface.
   * 
   * @param session
   *          The session to use for reading attributes. This session must have the appropriate
   *          rights; i.e. it must be a user-session, if it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  protected UserInterface(Session session, long objectHandle) throws TokenException {
    super(session, objectHandle);
    hardwareFeatureType_.setLongValue(FeatureType.USER_INTERFACE);
  }

  /**
   * The getInstance method of the HardwareFeature class uses this method to create an instance of a
   * PKCS#11 user interface.
   * 
   * @param session
   *          The session to use for reading attributes. This session must have the appropriate
   *          rights; i.e. it must be a user-session, if it is a private object.
   * @param objectHandle
   *          The object handle as given from the PKCS#111 module.
   * @return The object representing the PKCS#11 object. The returned object can be casted to the
   *         according sub-class.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  public static Object getInstance(Session session, long objectHandle)
      throws TokenException {
    return new UserInterface(session, objectHandle);
  }

  /**
   * Put all attributes of the given object into the attributes table of this object. This method is
   * only static to be able to access invoke the implementation of this method for each class
   * separately (see use in clone()).
   * 
   * @param object
   *          The object to handle.
   */
  protected static void putAttributesInTable(UserInterface object) {
    if (object == null) {
      throw new NullPointerException("Argument \"object\" must not be null.");
    }

    object.attributeTable_.put(Attribute.PIXEL_X, object.pixelX_);
    object.attributeTable_.put(Attribute.PIXEL_Y, object.pixelY_);
    object.attributeTable_.put(Attribute.RESOLUTION, object.resolution_);
    object.attributeTable_.put(Attribute.CHAR_ROWS, object.charRows_);
    object.attributeTable_.put(Attribute.CHAR_COLUMNS, object.charColumns_);
    object.attributeTable_.put(Attribute.COLOR, object.color_);
    object.attributeTable_.put(Attribute.BITS_PER_PIXEL, object.bitsPerPixel_);
    object.attributeTable_.put(Attribute.CHAR_SETS, object.charSets_);
    object.attributeTable_.put(Attribute.ENCODING_METHODS, object.encodingMethods_);
    object.attributeTable_.put(Attribute.MIME_TYPES, object.mimeTypes_);
  }

  /**
   * Allocates the attribute objects for this class and adds them to the attribute table.
   */
  protected void allocateAttributes() {
    super.allocateAttributes();

    pixelX_ = new LongAttribute(Attribute.PIXEL_X);
    pixelY_ = new LongAttribute(Attribute.PIXEL_Y);
    resolution_ = new LongAttribute(Attribute.RESOLUTION);
    charRows_ = new LongAttribute(Attribute.CHAR_ROWS);
    charColumns_ = new LongAttribute(Attribute.CHAR_COLUMNS);
    color_ = new BooleanAttribute(Attribute.COLOR);
    bitsPerPixel_ = new LongAttribute(Attribute.BITS_PER_PIXEL);
    charSets_ = new ByteArrayAttribute(Attribute.CHAR_SETS);
    encodingMethods_ = new ByteArrayAttribute(Attribute.ENCODING_METHODS);
    mimeTypes_ = new ByteArrayAttribute(Attribute.MIME_TYPES);

    putAttributesInTable(this);
  }

  /**
   * Create a (deep) clone of this object.
   * 
   * @return A clone of this object.
   */
  public java.lang.Object clone() {
    UserInterface clone = (UserInterface) super.clone();

    clone.pixelX_ = (LongAttribute) this.pixelX_.clone();
    clone.pixelY_ = (LongAttribute) this.pixelY_.clone();
    clone.resolution_ = (LongAttribute) this.resolution_.clone();
    clone.charRows_ = (LongAttribute) this.charRows_.clone();
    clone.charColumns_ = (LongAttribute) this.charColumns_.clone();
    clone.color_ = (BooleanAttribute) this.color_.clone();
    clone.bitsPerPixel_ = (LongAttribute) this.bitsPerPixel_.clone();
    clone.charSets_ = (ByteArrayAttribute) this.charSets_.clone();
    clone.encodingMethods_ = (ByteArrayAttribute) this.encodingMethods_.clone();
    clone.mimeTypes_ = (ByteArrayAttribute) this.mimeTypes_.clone();

    putAttributesInTable(clone); // put all cloned attributes into the new table

    return clone;
  }

  /*
   * (non-Javadoc)
   * 
   * @see iaik.pkcs.pkcs11.objects.HardwareFeature#equals(java.lang.Object)
   */
  public boolean equals(java.lang.Object obj) {
    if (this == obj)
      return true;
    if (!super.equals(obj))
      return false;
    if (getClass() != obj.getClass())
      return false;
    UserInterface other = (UserInterface) obj;
    if (bitsPerPixel_ == null) {
      if (other.bitsPerPixel_ != null)
        return false;
    } else if (!bitsPerPixel_.equals(other.bitsPerPixel_))
      return false;
    if (charColumns_ == null) {
      if (other.charColumns_ != null)
        return false;
    } else if (!charColumns_.equals(other.charColumns_))
      return false;
    if (charRows_ == null) {
      if (other.charRows_ != null)
        return false;
    } else if (!charRows_.equals(other.charRows_))
      return false;
    if (charSets_ == null) {
      if (other.charSets_ != null)
        return false;
    } else if (!charSets_.equals(other.charSets_))
      return false;
    if (color_ == null) {
      if (other.color_ != null)
        return false;
    } else if (!color_.equals(other.color_))
      return false;
    if (encodingMethods_ == null) {
      if (other.encodingMethods_ != null)
        return false;
    } else if (!encodingMethods_.equals(other.encodingMethods_))
      return false;
    if (mimeTypes_ == null) {
      if (other.mimeTypes_ != null)
        return false;
    } else if (!mimeTypes_.equals(other.mimeTypes_))
      return false;
    if (pixelX_ == null) {
      if (other.pixelX_ != null)
        return false;
    } else if (!pixelX_.equals(other.pixelX_))
      return false;
    if (pixelY_ == null) {
      if (other.pixelY_ != null)
        return false;
    } else if (!pixelY_.equals(other.pixelY_))
      return false;
    if (resolution_ == null) {
      if (other.resolution_ != null)
        return false;
    } else if (!resolution_.equals(other.resolution_))
      return false;
    return true;
  }

  /**
   * Gets the pixel x.
   * 
   * @return the pixel x
   */
  public LongAttribute getPixelX() {
    return this.pixelX_;
  }

  /**
   * Gets the pixel y.
   * 
   * @return the pixel y
   */
  public LongAttribute getPixelY() {
    return pixelY_;
  }

  /**
   * Gets the resolution.
   * 
   * @return the resolution
   */
  public LongAttribute getResolution() {
    return resolution_;
  }

  /**
   * Gets the char rows.
   * 
   * @return the char rows
   */
  public LongAttribute getCharRows() {
    return charRows_;
  }

  /**
   * Gets the char columns.
   * 
   * @return the char columns
   */
  public LongAttribute getCharColumns() {
    return charColumns_;
  }

  /**
   * Gets the color.
   * 
   * @return the color
   */
  public BooleanAttribute getColor() {
    return color_;
  }

  /**
   * Gets the bits per pixel.
   * 
   * @return the bits per pixel
   */
  public LongAttribute getBitsPerPixel() {
    return bitsPerPixel_;
  }

  /**
   * Gets the char sets.
   * 
   * @return the char sets
   */
  public ByteArrayAttribute getCharSets() {
    return charSets_;
  }

  /**
   * Gets the encoding methods.
   * 
   * @return the encoding methods
   */
  public ByteArrayAttribute getEncodingMethods() {
    return encodingMethods_;
  }

  /**
   * Gets the mime types.
   * 
   * @return the mime types
   */
  public ByteArrayAttribute getMimeTypes() {
    return mimeTypes_;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object.
   */
  public int hashCode() {
    return pixelX_.hashCode() ^ pixelY_.hashCode() ^ resolution_.hashCode()
        ^ charRows_.hashCode() ^ charColumns_.hashCode() ^ color_.hashCode()
        ^ bitsPerPixel_.hashCode() ^ charSets_.hashCode() ^ encodingMethods_.hashCode()
        ^ mimeTypes_.hashCode();
  }

  /**
   * Read the values of the attributes of this object from the token.
   * 
   * @param session
   *          The session handle to use for reading attributes. This session must have the
   *          appropriate rights; i.e. it must be a user-session, if it is a private object.
   * @exception TokenException
   *              If getting the attributes failed.
   */
  public void readAttributes(Session session) throws TokenException {
    super.readAttributes(session);

    Object.getAttributeValues(session, objectHandle_, new Attribute[] { pixelX_, pixelY_,
        resolution_, charRows_, charColumns_, color_, bitsPerPixel_, charSets_,
        encodingMethods_, mimeTypes_ });
  }

  /**
   * This method returns a string representation of the current object. The output is only for
   * debugging purposes and should not be used for other purposes.
   * 
   * @return A string presentation of this object for debugging output.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer(256);

    buffer.append(super.toString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Pixel X: ");
    buffer.append(pixelX_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Pixel Y: ");
    buffer.append(pixelY_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Resolution: ");
    buffer.append(resolution_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Char Rows: ");
    buffer.append(charRows_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Char Columns: ");
    buffer.append(charColumns_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Color: ");
    buffer.append(color_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Bits per Pixel: ");
    buffer.append(bitsPerPixel_.getValueString());

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Char sets:");
    try {
      buffer.append(new String(charSets_.getByteArrayValue(), "ASCII"));
    } catch (UnsupportedEncodingException ex) {
      buffer.append(new String(charSets_.getByteArrayValue()));
    }

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Encoding methods: ");
    try {
      buffer.append(new String(encodingMethods_.getByteArrayValue(), "ASCII"));
    } catch (UnsupportedEncodingException ex) {
      buffer.append(new String(encodingMethods_.getByteArrayValue()));
    }

    buffer.append(Constants.NEWLINE);
    buffer.append(Constants.INDENT);
    buffer.append("Mime Types: ");
    try {
      buffer.append(new String(mimeTypes_.getByteArrayValue(), "ASCII"));
    } catch (UnsupportedEncodingException ex) {
      buffer.append(new String(mimeTypes_.getByteArrayValue()));
    }

    return buffer.toString();
  }
}
