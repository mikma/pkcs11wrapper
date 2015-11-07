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

package demo.pkcs.pkcs11.wrapper.util;

import iaik.asn1.structures.AlgorithmID;
import iaik.pkcs.pkcs7.EnvelopedDataStream;
import iaik.pkcs.pkcs7.RecipientInfo;
import iaik.security.provider.IAIK;
import iaik.x509.X509Certificate;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;

/**
 * This helper class encrypts the given data using TrippleDES and encrypts the symmetric key using
 * the public key in the given certificate.
 */
public class EncryptPKCS7EnvelopedData {

  /**
   * Usage: EncryptPKCS7EnvelopedData data-to-encrypt-file recipient-certificate
   * PKCS#7-enveloped-data-file
   */
  public static void main(String[] args) throws NoSuchAlgorithmException,
      CertificateException, IOException {
    if (args.length != 3) {
      printUsage();
      throw new IOException("Missing argument!");
    }

    Security.addProvider(new IAIK());

    System.out.println("Encrypting data from file: " + args[0]);
    InputStream dataInputStream = new FileInputStream(args[0]);

    EnvelopedDataStream envelopedData = new EnvelopedDataStream(dataInputStream,
        AlgorithmID.des_EDE3_CBC);

    System.out.println("using recipient certificate from: " + args[1]);
    InputStream certificateInputStream = new FileInputStream(args[1]);

    X509Certificate recipientCertificate = new X509Certificate(certificateInputStream);
    System.out.println("which is: ");
    System.out.println(recipientCertificate.toString(true));

    RecipientInfo recipient = new RecipientInfo(recipientCertificate,
        AlgorithmID.rsaEncryption);

    envelopedData.setRecipientInfos(new RecipientInfo[] { recipient });

    System.out.println("writing enveloped data to: " + args[2]);
    OutputStream envelopedDataOutputStream = new FileOutputStream(args[2]);
    envelopedData.writeTo(envelopedDataOutputStream);
  }

  public static void printUsage() {
    System.out
        .println("Usage: EncryptPKCS7EnvelopedData <data to encrypt file> <recipient certificate> <PKCS#7 enveloped data file>");
    System.out
        .println(" e.g.: EncryptPKCS7EnvelopedData contentData.dat recipientCertificte.der envelopedData.p7");
  }

}
