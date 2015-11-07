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

import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_NOTIFY;
import iaik.pkcs.pkcs11.wrapper.CK_TOKEN_INFO;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;

/**
 * Objects of this class represent PKCS#11 tokens. The application can get information on the token,
 * manage sessions and initialize the token. Notice that objects of this class can become valid at
 * any time. This is, the user can remove the token at any time and any subsequent calls to the
 * corresponding object will fail with an exception (e.g. an exception with the error code
 * PKCS11Constants.CKR_DEVICE_REMOVED). First, the application may want to find out what
 * cryptographic algorithms the token supports. Implementations of such algorithms on a token are
 * called mechanisms in the context of PKCS#11. The code for this may look something like this.
 * 
 * <pre>
 * <code>
 *   List supportedMechanisms = Arrays.asList(token.getMechanismList());
 * 
 *   // check, if the token supports the required mechanism
 *   if (!supportedMechanisms.contains(Mechanism.RSA_PKCS)) {
 *     System.out.print("This token does not support the RSA PKCS mechanism!");
 *     System.out.flush();
 *     throw new TokenException("RSA not supported!");
 *   } else {
 *     MechanismInfo rsaMechanismInfo = token.getMechanismInfo(Mechanism.RSA_PKCS);
 *     // check, if the mechanism supports the required operation
 *     if (!rsaMechanismInfo.isDecrypt()) {
 *        System.out.print("This token does not support RSA decryption according to PKCS!");
 *        System.out.flush();
 *        throw new TokenException("RSA signing not supported!");
 *     }
 *   }
 * </code>
 * </pre>
 * 
 * Being sure that the token supports the required mechanism, the application can open a session.
 * For example, it may call
 * 
 * <pre>
 * <code>
 *  Session session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
 * </code>
 * </pre>
 * 
 * to open a simple read-only session.
 * 
 * @see iaik.pkcs.pkcs11.Mechanism
 * @see iaik.pkcs.pkcs11.MechanismInfo
 * @see iaik.pkcs.pkcs11.Session
 * @see iaik.pkcs.pkcs11.TokenInfo
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (slot_ <> null)
 */
public class Token {

  /**
   * This interface defines constants for the type of session that should be opened upon a call to
   * openSession. The version 2.x of PKCS#11 only allows serial sessions. Both types are defined
   * just for the sake of completeness.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface SessionType {

    /**
     * Indicates a parallel session. (No longer supported by PKCS#11!).
     */
    public static boolean PARALLEL_SESSION = false;

    /**
     * Indicates a serial session. This is the only type of session currently allowed by PKCS#11.
     */
    public static boolean SERIAL_SESSION = true;

  }

  /**
   * This interface defines constants that specify the read/write behavior of a session. There are
   * read-only and read-write sessions. These constants are used for openSession calls.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface SessionReadWriteBehavior {

    /**
     * Indicates a read-only session.
     */
    public static boolean RO_SESSION = false;

    /**
     * Indicates a read-write session.
     */
    public static boolean RW_SESSION = true;

  }

  /**
   * The reference to the slot.
   */
  protected Slot slot_;

  /**
   * True, if UTF8 encoding is used as character encoding for character array attributes and PINs.
   */
  protected boolean useUtf8Encoding_;

  /**
   * The constructor that takes a reference to the module and the slot ID.
   * 
   * @param slot
   *          The reference to the slot.
   * @preconditions (module <> null)
   * 
   */
  protected Token(Slot slot) {
    if (slot == null) {
      throw new NullPointerException("Argument \"slot\" must not be null.");
    }
    slot_ = slot;
    useUtf8Encoding_ = slot.useUtf8Encoding_;
  }

  /**
   * Compares the slot_ of this object with the other object. Returns only true, if those are equal
   * in both objects.
   * 
   * @param otherObject
   *          The other Token object.
   * @return True, if other is an instance of Token and the slot_ member varialbe of both objects
   *         are equal. False, otherwise.
   */
  public boolean equals(Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof Token) {
      Token other = (Token) otherObject;
      equal = (this == other) || this.slot_.equals(other.slot_);
    }

    return equal;
  }

  /**
   * Get the slot that created this Token object.
   * 
   * @return The slot of this token.
   */
  public Slot getSlot() {
    return slot_;
  }

  /**
   * Get the ID of this token. This is the ID of the slot this token resides in.
   * 
   * @return The ID of this token.
   */
  public long getTokenID() {
    return slot_.getSlotID();
  }

  /**
   * Get information about this token.
   * 
   * @return An object containing information about this token.
   * @exception TokenException
   *              If reading the information fails.
   * 
   * @postconditions (result <> null)
   */
  public TokenInfo getTokenInfo() throws TokenException {
    CK_TOKEN_INFO ckTokenInfo = slot_.getModule().getPKCS11Module()
        .C_GetTokenInfo(slot_.getSlotID());

    return new TokenInfo(ckTokenInfo);
  }

  /**
   * Get the list of mechanisms that this token supports. An application can use this method to
   * determine, if this token supports the required mechanism.
   * 
   * @return An array of Mechanism objects. Each describes a mechansim that this token can perform.
   *         This array may be empty but not null.
   * @exception TokenException
   *              If reading the list of supported mechansisms fails.
   * 
   * @postconditions (result <> null)
   */
  public Mechanism[] getMechanismList() throws TokenException {
    long[] mechanismIdList = slot_.getModule().getPKCS11Module()
        .C_GetMechanismList(slot_.getSlotID());
    Mechanism[] mechanisms = new Mechanism[mechanismIdList.length];
    for (int i = 0; i < mechanisms.length; i++) {
      mechanisms[i] = new Mechanism(mechanismIdList[i]);
    }

    return mechanisms;
  }

  /**
   * Get mor information about one supported mechanism. The application can find out, e.g. if an
   * algorithm supports the certain key length.
   * 
   * @param mechanism
   *          A mechanism that is supported by this token.
   * @return An information object about the concerned mechanism.
   * @exception TokenException
   *              If reading the information fails, or if the mechansim is not supported by this
   *              token.
   * @preconditions (mechanism <> null) and (getMechanismList() contains mechanism)
   * @postconditions (result <> null)
   */
  public MechanismInfo getMechanismInfo(Mechanism mechanism) throws TokenException {
    long mechanismCode = mechanism.getMechanismCode();
    CK_MECHANISM_INFO ckMechanismInfo = slot_.getModule().getPKCS11Module()
        .C_GetMechanismInfo(slot_.getSlotID(), mechanismCode);

    return new MechanismInfo(ckMechanismInfo);
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the slot ID.
   */
  public int hashCode() {
    return slot_.hashCode();
  }

  /**
   * Initialize the token. Attention: any data on the token will be lost! An token must normally be
   * initialized before its first use.
   * 
   * @param pin
   *          If the token is not initialized yet, this PIN becomes the security officer (admin)
   *          PIN. If the token is already initialized, this PIN must be the correct security
   *          officer PIN of this token. Otherwise the operation will fail. If the token slot has
   *          build-in means to verify the user (e.g. a PIN-pad on the card reader), this parameter
   *          can be null.
   * @param label
   *          The label to give to the token. If this string is longer than 32 characters, it will
   *          be cut off at the end to be exactly 32 characters in length. If it is shorter than 32
   *          characters, the label is filled up with the blank character (' ') to be exactly 32
   *          characters in length.
   * @exception TokenException
   *              If the initialization fails.
   */
  public void initToken(char[] pin, String label) throws TokenException {
    char[] labelChars = Util.toPaddedCharArray(label, 32, ' ');
    slot_.getModule().getPKCS11Module()
        .C_InitToken(slot_.getSlotID(), pin, labelChars, useUtf8Encoding_);
  }

  /**
   * Open a new session to perfom operations on this token. Notice that all session within one
   * application (system process) have the same login state.
   * 
   * @param serialSession
   *          Must be SessionType.SERIAL_SESSION. (For the sake of completeness)
   * @param rwSession
   *          Must be either SessionReadWriteBehavior.RO_SESSION for read-only sessions or
   *          SessionReadWriteBehavior.RW_SESSION for read-write sessions.
   * @param application
   *          Object to be supplied upon notify callback. May be null. (Not implemented yet!).
   * @param notify
   *          For notifications via callback. may be null. (Not implemented yet!)
   * @return The newly opened session.
   * @exception TokenException
   *              If the session could not be opened.
   * @preconditions (serialSession == SessionType.SERIAL_SESSION)
   * @postconditions (result <> null)
   */
  public Session openSession(boolean serialSession, boolean rwSession,
      Object application, final Notify notify) throws TokenException {
    long flags = 0L;
    flags |= (serialSession) ? PKCS11Constants.CKF_SERIAL_SESSION : 0L;
    flags |= (rwSession) ? PKCS11Constants.CKF_RW_SESSION : 0L;
    final Session newSession = new Session(this, -1); // we need it for the notify already here
    CK_NOTIFY ckNotify = null;
    if (notify != null) {
      ckNotify = new CK_NOTIFY() {
        public void CK_NOTIFY(long hSession, long event, Object pApplication)
            throws PKCS11Exception {
          boolean surrender = (event & PKCS11Constants.CKN_SURRENDER) != 0L;
          notify.notify(newSession, surrender, pApplication);
        }
      };
    }
    long sessionHandle = slot_.getModule().getPKCS11Module()
        .C_OpenSession(slot_.getSlotID(), flags, application, ckNotify);
    newSession.sessionHandle_ = sessionHandle; // now we have the session handle available

    return newSession;
  }

  /**
   * Close all open sessions of this token. All subsequently opened session will be public sessions
   * (i.e. not logged in) by default.
   * 
   * @exception TokenException
   *              If closing all session fails.
   */
  public void closeAllSessions() throws TokenException {
    slot_.getModule().getPKCS11Module().C_CloseAllSessions(slot_.getSlotID());
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of this object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Token in Slot: ");
    buffer.append(slot_.toString());

    return buffer.toString();
  }

}
