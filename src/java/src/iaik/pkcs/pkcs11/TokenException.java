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

package iaik.pkcs.pkcs11;

/**
 * The base class for all exceptions in this package. It is able to wrap a other exception from a
 * lower layer.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class TokenException extends Exception {

  /**
   * An encapsulated (inner) exception. Possibly, an exception from a lower layer that ca be
   * propagated to a higher layer only in wrapped form.
   */
  protected Exception encapsulatedException_;

  /**
   * The default constructor.
   * 
   */
  public TokenException() {
    super();
  }

  /**
   * Constructor taking an exception message.
   * 
   * @param message
   *          The message giving details about the exception to ease debugging.
   */
  public TokenException(String message) {
    super(message);
  }

  /**
   * Constructor taking an other exception to wrap.
   * 
   * @param encapsulatedException
   *          The other exception the wrap into this.
   */
  public TokenException(Exception encapsulatedException) {
    super();
    encapsulatedException_ = encapsulatedException;
  }

  /**
   * Constructor taking a message for this exception and an other exception to wrap.
   * 
   * @param message
   *          The message giving details about the exception to ease debugging.
   * @param encapsulatedException
   *          The other exception the wrap into this.
   */
  public TokenException(String message, Exception encapsulatedException) {
    super(message);
    encapsulatedException_ = encapsulatedException;
  }

  /**
   * Get the encapsulated (wrapped) exception. May be null.
   * 
   * @return The encasulated (wrapped) exception, or null if there is no inner exception.
   */
  public Exception getEncapsulatedException() {
    return encapsulatedException_;
  }

  /**
   * Returns the string representation of this exception, including the string representation of the
   * wrapped (encapsulated) exception.
   * 
   * @return The string representation of exception.
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer(super.toString());

    if (encapsulatedException_ != null) {
      buffer.append(", Encasulated Exception: ");
      buffer.append(encapsulatedException_.toString());
    }

    return buffer.toString();
  }

}
