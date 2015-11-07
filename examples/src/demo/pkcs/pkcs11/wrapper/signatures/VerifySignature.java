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

package demo.pkcs.pkcs11.wrapper.signatures;

import iaik.security.provider.IAIK;
import iaik.utils.Util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifySignature {

  protected X509Certificate certificate_;

  protected Signature verifyEngine_;

  public VerifySignature(X509Certificate certificate, String algorithm)
      throws GeneralSecurityException {
    certificate_ = certificate;
    // verifyEngine_ = Signature.getInstance(algorithm, "IAIK");
    verifyEngine_ = Signature.getInstance(algorithm);
    verifyEngine_.initVerify(certificate.getPublicKey());
  }

  public boolean verify(InputStream data, byte[] signature) throws IOException,
      GeneralSecurityException {
    byte[] buffer = new byte[1024];
    int bytesRead;

    while ((bytesRead = data.read(buffer, 0, buffer.length)) >= 0) {
      verifyEngine_.update(buffer, 0, bytesRead);
    }

    return verifyEngine_.verify(signature);
  }

  /**
   * Usage: VerifySignature data-file signature-file X.509-certificate-file algorithm
   */
  public static void main(String[] args) throws IOException, GeneralSecurityException {
    if (args.length < 4) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    FileInputStream dataInput = new FileInputStream(args[0]);
    byte[] signature = Util.readStream(new FileInputStream(args[1]));
    FileInputStream certificateInput = new FileInputStream(args[2]);
    Security.addProvider(new IAIK());
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509",
        "IAIK");
    // CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    X509Certificate certificate = (X509Certificate) certificateFactory
        .generateCertificate(certificateInput);

    VerifySignature verifier = new VerifySignature(certificate, args[3]);

    if (verifier.verify(dataInput, signature)) {
      System.out.println("Verified signature successfully.");
    } else {
      System.out.println("Signature is INVALID.");
      // Cipher rsa = Cipher.getInstance("RSA/ECB/NoPadding");
      // rsa.init(Cipher.DECRYPT_MODE, certificate.getPublicKey());
      // byte[] signedBlock = rsa.doFinal(signature);
      // System.out.println("Decrypted signature value is (hex):");
      // System.out.println(new BigInteger(1, signedBlock).toString(16));
    }
  }

  public static void printUsage() {
    System.out
        .println("Usage: VerifySignature <data file> <signature file> <X.509 certificate file> <algorithm>");
    System.out
        .println(" e.g.: VerifySignature data.dat signature.bin signerCertificate.der SHA1withRSA");
  }

}
