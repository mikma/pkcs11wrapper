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

package demo.pkcs.pkcs11.wrapper.adapters;

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.X509PublicKeyCertificate;

/**
 * This class encapsulates a key and an optional certificate.
 */
public class KeyAndCertificate {

  /**
   * The key.
   */
  protected Key key_;

  /**
   * This optional certificate.
   */
  protected X509PublicKeyCertificate certificate_;

  /**
   * Creates a new object that holds the given key and certificate.
   * 
   * @param key
   *          The key.
   * @param certificate
   *          The certificate.
   */
  public KeyAndCertificate(Key key, X509PublicKeyCertificate certificate) {
    key_ = key;
    certificate_ = certificate;
  }

  /**
   * Returns the certificate.
   * 
   * @return The certificate.
   */
  public X509PublicKeyCertificate getCertificate() {
    return certificate_;
  }

  /**
   * Returns the key.
   * 
   * @return The key.
   */
  public Key getKey() {
    return key_;
  }

  /**
   * Sets the certificate.
   * 
   * @param certificate
   *          The certificate.
   */
  public void setCertificate(X509PublicKeyCertificate certificate) {
    certificate_ = certificate;
  }

  /**
   * Sets the key.
   * 
   * @param key
   *          The key.
   */
  public void setKey(Key key) {
    key_ = key;
  }

}
