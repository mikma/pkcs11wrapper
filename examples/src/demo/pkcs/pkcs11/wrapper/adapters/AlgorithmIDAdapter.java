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

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import iaik.asn1.structures.AlgorithmID;

/**
 * This class is an adapter to enables an application to use a different implementation than the
 * standard implementation with the IAIK-JCE.
 */
public class AlgorithmIDAdapter extends AlgorithmID {

  /**
   * The delegate object to use, if no concrete implementation is set for a certain engine class.
   */
  protected AlgorithmID delegate_;

  /**
   * This is the signature engine to use for this object.
   */
  protected Signature signatureEngine_;

  /**
   * Creates a new AlgorithmIDAdapter that uses the given delegate object to get the .
   * 
   * @param delegate
   *          The object to get other implementations from, implementations not provided by this
   *          object.
   */
  public AlgorithmIDAdapter(AlgorithmID delegate) {
    super(delegate.getAlgorithm());
    delegate_ = delegate;
  }

  /**
   * Set the implementation to use as signature instance.
   * 
   * @param signatureEngine
   *          The implementation of the signature class to return upon a call to
   *          getSignatureInstance(). If null, the implementation is unset.
   */
  public void setSignatureInstance(Signature signatureEngine) {
    signatureEngine_ = signatureEngine;
  }

  /**
   * If a concrete signature implementation was set using setSignatureInstance(Signature), this
   * method returns this. Otherwise, it delegates the call to the delegate of this object.
   * 
   * @return The signature engine to use for this algorthim.
   * @exception NoSuchAlgorithmException
   *              If there is no signature implementation for this algorithm.
   */
  public Signature getSignatureInstance() throws NoSuchAlgorithmException {
    return (signatureEngine_ != null) ? signatureEngine_ : super.getSignatureInstance();
  }

  /**
   * If a concrete signature implementation was set using setSignatureInstance(Signature) and the
   * provider name is null, this method returns this set signature implementation; otherwise, it
   * delegates the call to the delegate of this object.
   * 
   * @return The signature engine to use for this algorthim.
   * @exception NoSuchAlgorithmException
   *              If there is no signature implementation for this algorithm.
   */
  public Signature getSignatureInstance(String providerName)
      throws NoSuchAlgorithmException {
    return (providerName == null) ? getSignatureInstance() : super
        .getSignatureInstance(providerName);
  }

}
