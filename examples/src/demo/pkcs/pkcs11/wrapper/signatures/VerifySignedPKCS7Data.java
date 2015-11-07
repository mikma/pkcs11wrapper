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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.security.SignatureException;

import iaik.pkcs.pkcs7.SignedDataStream;
import iaik.pkcs.pkcs7.SignerInfo;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

/**
 * This helper class simply verifies the signature of a PKCS#7 signed data object and extracts the
 * verified content data.
 */
public class VerifySignedPKCS7Data {

  /**
   * Usage: VerifySignedPKCS7Data PKCS#7-signed-data-file verified-content-data
   */
  public static void main(String[] args) throws Exception {
    if ((args.length != 1) && (args.length != 2)) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    try {
      Security.addProvider(new IAIK());

      System.out.println("Verifying PKCS#7 signed data from file: " + args[0]);
      InputStream dataInput = new FileInputStream(args[0]);

      SignedDataStream signedData = new SignedDataStream(dataInput);

      InputStream contentStream = signedData.getInputStream();
      OutputStream verifiedContentStream = (args.length == 2) ? new FileOutputStream(
          args[1]) : null;
      byte[] buffer = new byte[1024];
      int bytesRead;

      if (verifiedContentStream != null) {
        while ((bytesRead = contentStream.read(buffer)) > 0) {
          verifiedContentStream.write(buffer, 0, bytesRead);
        }
        verifiedContentStream.flush();
        verifiedContentStream.close();
        System.out.println("Verified content written to: " + args[1]);
        System.out
            .println("________________________________________________________________________________");
      } else {
        System.out.println("The signed content data is: ");
        System.out
            .println("________________________________________________________________________________");
        while ((bytesRead = contentStream.read(buffer)) > 0) {
          System.out.write(buffer, 0, bytesRead);
        }
        System.out.println();
        System.out
            .println("________________________________________________________________________________");
      }

      // get the signer infos
      SignerInfo[] signerInfos = signedData.getSignerInfos();
      // verify the signatures
      for (int i = 0; i < signerInfos.length; i++) {
        try {
          // verify the signature for SignerInfo at index i
          X509Certificate signerCertificate = signedData.verify(i);
          // if the signature is OK the certificate of the signer is returned
          System.out.println("Signature OK from signer with certificate: ");
          System.out.println(signerCertificate);
          System.out.println();
        } catch (SignatureException ex) {
          // if the signature is not OK a SignatureException is thrown
          System.out.println("Signature ERROR from signer with certificate: ");
          System.out.println(signedData.getCertificate(signerInfos[i]
              .getIssuerAndSerialNumber()));
          System.out.println();
          ex.printStackTrace();
        }
      }

    } catch (Throwable thr) {
      thr.printStackTrace();
    }
  }

  public static void printUsage() {
    System.out
        .println("Usage: VerifySignedPKCS7Data <PKCS#7 signed data file> <verified content data>");
    System.out
        .println(" e.g.: VerifySignedPKCS7Data signedData.p7 verifiedContentData.dat");
  }

}
