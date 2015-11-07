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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.CharArrayAttribute;
import iaik.pkcs.pkcs11.objects.GenericSecretKey;
import iaik.pkcs.pkcs11.objects.GenericTemplate;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import iaik.utils.CryptoUtils;
import iaik.utils.Util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

/**
 * This demo provides methods to change the encoding of key and certificate labels from the old
 * ASCII encoding to UTF8 encoding (which is now used per default). This is only necessary for
 * special characters. patchAllLabels changes all object labels to UTF8 without prior checks.
 * findAndPatchOldLabels verifies if the labels are already UTF8 encoded and - if not - changes
 * their encoding to UTF8.
 * 
 */
public class PatchToUTF8LabelsDemo {

  private static String testLabel1;
  private static String testLabel2;
  private static String testLabel3;
  private static String testLabel4 = "aNormalLabel";
  private static Module pkcs11Module_ = null;

  static PrintWriter output_;
  static BufferedReader input_;

  private Session utf8Session_ = null;
  private Session asciiSession_ = null;
  private String modulename_ = null;
  private String pin_ = null;
  private int slotID_ = -1;
  private boolean loggedIn_ = false;

  static {
    try {
      // output_ = new PrintWriter(new FileWriter("demolog.txt"), true);
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    } catch (Throwable thr) {
      thr.printStackTrace();
      output_ = new PrintWriter(System.out, true);
      input_ = new BufferedReader(new InputStreamReader(System.in));
    }
  }

  /**
   * Usage: PatchToUTF8LabelsDemo PKCS#11-module [slot-index] [user-PIN]
   */
  public static void main(String[] args) throws Exception {
    if (args.length < 1) {
      printUsage();
    } else {
      testLabel1 = new String(Util.toByteArray("C3:82:C3:A8:C3:AF:C3:B5:C3:BD"), "UTF8");
      testLabel2 = new String(Util.toByteArray("C3:A4:65:69:C3:B6:C3:BC:C3:9F"), "UTF8");
      testLabel3 = new String(Util.toByteArray("C2:B5:C3:9A:C3:87:C3:A6"), "UTF8");
      PatchToUTF8LabelsDemo demo = new PatchToUTF8LabelsDemo();
      demo.setTokenDetails(args);
      // generate old keys
      demo.generateKey(testLabel1);
      demo.generateKey(testLabel2);
      demo.generateKey(testLabel4);
      System.out.println("print old key labels:");
      demo.printKeyEntries(false);
      // assuming all labels use old encoding -> convert all labels to utf8
      // encoding
      demo.patchAllLabels();
      System.out.println("print new utf8 encoded key labels:");
      demo.printKeyEntries(true);
      demo.generateKey(testLabel3);
      // check if label is already utf8 encoded -> convert only not utf8 encoded
      // labels
      demo.findAndPatchOldLabels();
      System.out.println("print new utf8 encoded key labels:");
      demo.printKeyEntries(true);
      demo.deleteAllDemoEntries();
      // close sessions
      Session session = demo.getSession(false);
      session.closeSession();
      session = demo.getSession(true);
      session.closeSession();
      pkcs11Module_.finalize(null);
    }
  }

  private void setTokenDetails(String[] args) {
    if (args.length > 3) {
      modulename_ = args[0];
      slotID_ = Integer.parseInt(args[1]);
      pin_ = args[2];
    } else {
      if (args.length > 0)
        modulename_ = args[0];
      if (args.length > 1)
        slotID_ = Integer.parseInt(args[1]);
      if (args.length > 2)
        pin_ = args[2];
    }
  }

  private void findAndPatchOldLabels() throws Exception {
    Session session = getSession(false);
    session.findObjectsInit(null);
    Object[] objects = session.findObjects(1);
    while (objects.length > 0) {
      if (objects[0] instanceof Key) {
        Key key = (Key) objects[0];
        char[] label = key.getLabel().getCharArrayValue();
        if (label != null) {
          String utf8String = isAlreadyUtf8(label);
          if (utf8String == null) {
            System.out.print(new String(label) + " - will be patched");
            toUtf8(key);
          } else {
            System.out.print(utf8String + " - already utf8 encoded");
          }
        }
        System.out.println();
      }
      objects = session.findObjects(1);
    }
    session.findObjectsFinal();
  }

  private void patchAllLabels() throws Exception {
    Session session = getSession(false);
    session.findObjectsInit(null);
    Object[] objects = session.findObjects(1);
    while (objects.length > 0) {
      if (objects[0] instanceof Key) {
        Key key = (Key) objects[0];
        toUtf8(key);
      }
      objects = session.findObjects(1);
    }
    session.findObjectsFinal();
  }

  private void toUtf8(Key key) throws Exception {
    // convert label
    char[] label = key.getLabel().getCharArrayValue();
    if (label != null) {
      byte[] encoding = new String(label).getBytes("UTF8");
      String utf8String = new String(byteToCharArray(encoding));
      // can't overwrite existing entry
      Session session = getSession(false);
      GenericTemplate template = new GenericTemplate();
      CharArrayAttribute labelAttr = new CharArrayAttribute(new Long(
          PKCS11Constants.CKA_LABEL));
      labelAttr.setCharArrayValue(utf8String.toCharArray());
      template.addAttribute(labelAttr);
      try {
        session.setAttributeValues(key, template);
      } catch (PKCS11Exception e) {
        if (e.getErrorCode() == PKCS11Constants.CKR_ATTRIBUTE_READ_ONLY) {
          // try copy object
          session.copyObject(key, template);
          // if everything OK delete old object
          session.destroyObject(key);
        } else {
          throw e;
        }
      }

    }
  }

  private String isAlreadyUtf8(char[] label) throws Exception {
    byte[] encoding = charToByteArray(label);
    String utf8String = new String(encoding, "UTF8");
    byte[] newEncoding = utf8String.getBytes("UTF8");
    if (CryptoUtils.equalsBlock(encoding, newEncoding)) {
      return utf8String;
    } else {
      return null;
    }
  }

  private void printKeyEntries(boolean useUtf8) throws Exception {
    Session session = getSession(useUtf8);
    session.findObjectsInit(null);
    Object[] objects = session.findObjects(1);
    while (objects.length > 0) {
      if (objects[0] instanceof Key) {
        Key key = (Key) objects[0];
        String label = "null";
        char[] labelChars = key.getLabel().getCharArrayValue();
        if (labelChars != null) {
          label = new String(labelChars);
        }
        System.out.println(label);
      }
      objects = session.findObjects(1);
    }
    session.findObjectsFinal();
  }

  private void deleteAllDemoEntries() throws Exception {
    Session session = getSession(true);
    GenericTemplate template = new GenericTemplate();
    String[] labels = new String[] { testLabel1, testLabel2, testLabel3, testLabel4 };
    for (int i = 0; i < labels.length; i++) {
      String label = labels[i];
      CharArrayAttribute attribute = new CharArrayAttribute(new Long(
          PKCS11Constants.CKA_LABEL));
      attribute.setCharArrayValue(label.toCharArray());
      template.addAttribute(attribute);
      session.findObjectsInit(template);
      Object[] objects = session.findObjects(1);
      while (objects.length > 0) {
        session.destroyObject(objects[0]);
        objects = session.findObjects(1);
      }
      session.findObjectsFinal();
    }
  }

  private byte[] charToByteArray(char[] label) {
    byte[] encoding = new byte[label.length];
    for (int i = 0; i < label.length; i++) {
      encoding[i] = (byte) (label[i] & 0xFF);
    }
    return encoding;
  }

  private char[] byteToCharArray(byte[] encoding) {
    char[] label = new char[encoding.length];
    for (int i = 0; i < encoding.length; i++) {
      label[i] = (char) (encoding[i] & 0xFF);
    }
    return label;
  }

  private boolean generateKey(String label) throws Exception {
    Session session = getSession(false);
    SecretKey template;
    Mechanism keyGenerationMechanism;
    List supportedMechanisms = Arrays.asList(session.getToken().getMechanismList());
    if (supportedMechanisms.contains(Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN))) {
      keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_AES_KEY_GEN);
      AESSecretKey aesTemplate = new AESSecretKey();
      aesTemplate.getLabel().setCharArrayValue(label.toCharArray());
      aesTemplate.getToken().setBooleanValue(Boolean.TRUE);
      aesTemplate.getValueLen().setLongValue(new Long(16));
      template = aesTemplate;
    } else if (supportedMechanisms.contains(Mechanism
        .get(PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN))) {
      keyGenerationMechanism = Mechanism.get(PKCS11Constants.CKM_GENERIC_SECRET_KEY_GEN);
      GenericSecretKey genericTemplate = new GenericSecretKey();
      genericTemplate.getLabel().setCharArrayValue(label.toCharArray());
      genericTemplate.getToken().setBooleanValue(Boolean.TRUE);
      genericTemplate.getValueLen().setLongValue(new Long(16));
      template = genericTemplate;
    } else {
      output_.println("Mechanisms for generic or aes key generation not supported.");
      return false;
    }

    session.generateKey(keyGenerationMechanism, template);
    return true;
  }

  private Session initToken(boolean useUtf8Encoding) throws TokenException, IOException {
    if (pkcs11Module_ == null) {
      pkcs11Module_ = Module.getInstance(modulename_);
      pkcs11Module_.initialize(null);
    }
    Slot[] slots = pkcs11Module_.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);

    if (slots.length == 0) {
      output_.println("No slot with present token found!");
      throw new TokenException("No token found!");
    }

    Slot selectedSlot;
    if (slotID_ >= 0)
      selectedSlot = slots[slotID_];
    else
      selectedSlot = slots[0];

    selectedSlot.setUtf8Encoding(useUtf8Encoding);

    Token token = selectedSlot.getToken();
    Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
        Token.SessionReadWriteBehavior.RW_SESSION, null, null);

    // if we have to user PIN login user
    if (pin_ != null && !loggedIn_) {
      session.login(Session.UserType.USER, pin_.toCharArray());
      loggedIn_ = true;
    }
    return session;
  }

  private Session getSession(boolean useUtf8Encoding) throws TokenException, IOException {
    if (useUtf8Encoding) {
      if (utf8Session_ == null) {
        utf8Session_ = initToken(true);
      }
      return utf8Session_;
    } else {
      if (asciiSession_ == null) {
        asciiSession_ = initToken(false);
      }
      return asciiSession_;
    }
  }

  public static void printUsage() {
    output_
        .println("Usage: PatchToUTF8LabelsDemo <PKCS#11 module> [<slot-index>] [<user-PIN>]");
    output_.println(" e.g.: PatchToUTF8LabelsDemo cryptoki.dll");
    output_.println("The given DLL must be in the search path of the system.");
  }

}
