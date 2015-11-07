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

import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.Object;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.parameters.SSL3KeyMaterialParameters;
import iaik.pkcs.pkcs11.parameters.SSL3MasterKeyDeriveParameters;
import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_MECHANISM;
import iaik.pkcs.pkcs11.wrapper.CK_SESSION_INFO;
import iaik.pkcs.pkcs11.wrapper.CK_SSL3_KEY_MAT_PARAMS;
import iaik.pkcs.pkcs11.wrapper.CK_SSL3_MASTER_KEY_DERIVE_PARAMS;
import iaik.pkcs.pkcs11.wrapper.Constants;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.util.Vector;

/**
 * Session objects are used to perform cryptographic operations on a token. The application gets a
 * Session object by calling openSession on a certain Token object. Having the session object, the
 * application may log-in the user, if required.
 * 
 * <pre>
 * <code>
 *   TokenInfo tokenInfo = token.getTokenInfo();
 *   // check, if log-in of the user is required at all
 *   if (tokenInfo.isLoginRequired()) {
 *     // check, if the token has own means to authenticate the user; e.g. a PIN-pad on the reader
 *     if (tokenInfo.isProtectedAuthenticationPath()) {
 *       System.out.println("Please enter the user PIN at the PIN-pad of your reader.");
 *       session.login(Session.UserType.USER, null); // the token prompts the PIN by other means; e.g. PIN-pad
 *     } else {
 *       System.out.print("Enter user-PIN and press [return key]: ");
 *       System.out.flush();
 *       BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
 *       String userPINString = input.readLine();
 *       session.login(Session.UserType.USER, userPINString.toCharArray());
 *     }
 *   }
 * </code>
 * </pre>
 * 
 * With this session object the application can search for token objects and perform a cryptographic
 * operation. For example, to find private RSA keys that the application can use for signing, you
 * can write:
 * 
 * <pre>
 * <code>
 *   RSAPrivateKey privateSignatureKeyTemplate = new RSAPrivateKey();
 *   privateSignatureKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
 * 
 *   session.findObjectsInit(privateSignatureKeyTemplate);
 *   Object[] privateSignatureKeys;
 * 
 *   List signatureKeyList = new Vector(4);
 *   while ((privateSignatureKeys = session.findObjects(1)).length > 0) {
 *     signatureKeyList.add(privateSignatureKeys[0]);
 *   }
 *   session.findObjectsFinal();
 * </code>
 * </pre>
 * 
 * Having chosen one of this keys, the application can create a signature value using it.
 * 
 * <pre>
 * <code>
 *   // e.g. the encoded digest info object that contains an identifier of the
 *   // hash algorithm and the hash value
 *   byte[] toBeSigned;
 * 
 *   // toBeSigned = ... assign value
 * 
 *   RSAPrivateKey selectedSignatureKey;
 * 
 *   // selectedSignatureKey = ... assign one of the available signature keys
 * 
 *   // initialize for signing
 *   session.signInit(Mechanism.RSA_PKCS, selectedSignatureKey);
 * 
 *   // sign the data to be signed
 *   byte[] signatureValue = session.sign(toBeSigned);
 * </code>
 * </pre>
 * 
 * If the application does not need the session any longer, it should close the session.
 * 
 * <pre>
 * <code>
 *   session.closeSession();
 * </code>
 * </pre>
 * 
 * @see iaik.pkcs.pkcs11.objects.Object
 * @see iaik.pkcs.pkcs11.parameters.Parameters
 * @see iaik.pkcs.pkcs11.Session
 * @see iaik.pkcs.pkcs11.SessionInfo
 * @author Karl Scheibelhofer
 * @version 1.0
 * @invariants (pkcs11Module_ <> null)
 */
public class Session {

  /**
   * This interface defines the different user types of PKCS#11.
   * 
   * @author Karl Scheibelhofer
   * @version 1.0
   * 
   */
  public interface UserType {

    /**
     * This constant stands for the security officer.
     */
    public static boolean SO = false;

    /**
     * Thsi constant stands for the user (token owner).
     */
    public static boolean USER = true;

  }

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  protected Module module_;

  /**
   * A reference to the underlying PKCS#11 module to perform the operations.
   */
  protected PKCS11 pkcs11Module_;

  /**
   * The session handle to perform the operations with.
   */
  protected long sessionHandle_;

  /**
   * The token to perform the operations on.
   */
  protected Token token_;

  /**
   * True, if UTF8 encoding is used as character encoding for character array attributes and PINs.
   */
  private boolean useUtf8Encoding_;

  /**
   * Constructor taking the token and the session handle.
   * 
   * @param token
   *          The token this session operates with.
   * @param sessionHandle
   *          The session handle to perform the operations with.
   * @preconditions (token <> null)
   * 
   */
  protected Session(Token token, long sessionHandle) {
    if (token == null) {
      throw new NullPointerException("Argument \"token\" must not be null.");
    }
    token_ = token;
    module_ = token_.getSlot().getModule();
    pkcs11Module_ = module_.getPKCS11Module();
    sessionHandle_ = sessionHandle;
    useUtf8Encoding_ = token.useUtf8Encoding_;
  }

  /**
   * Initializes the user-PIN. Can only be called from a read-write security officer session. May be
   * used to set a new user-PIN if the user-PIN is locked.
   * 
   * @param pin
   *          The new user-PIN. This parameter may be null, if the token has a protected
   *          authentication path. Refer to the PKCS#11 standard for details.
   * @exception TokenException
   *              If the session has not the right to set the PIN of if the operation fails for some
   *              other reason.
   */
  public void initPIN(char[] pin) throws TokenException {
    pkcs11Module_.C_InitPIN(sessionHandle_, pin, useUtf8Encoding_);
  }

  /**
   * Set the user-PIN to a new value. Can only be called from a read-write sessions.
   * 
   * @param oldPin
   *          The old (current) user-PIN.
   * @param newPin
   *          The new value for the user-PIN.
   * @exception TokenException
   *              If setting the new PIN fails.
   */
  public void setPIN(char[] oldPin, char[] newPin) throws TokenException {
    pkcs11Module_.C_SetPIN(sessionHandle_, oldPin, newPin, useUtf8Encoding_);
  }

  /**
   * Closes this session.
   * 
   * @exception TokenException
   *              If closing the session failed.
   */
  public void closeSession() throws TokenException {
    pkcs11Module_.C_CloseSession(sessionHandle_);
  }

  /**
   * Compares the sessionHandle and token_ of this object with the other object. Returns only true,
   * if those are equal in both objects.
   * 
   * @param otherObject
   *          The other Session object.
   * @return True, if other is an instance of Token and the session handles and tokens of both
   *         objects are equal. False, otherwise.
   */
  public boolean equals(java.lang.Object otherObject) {
    boolean equal = false;

    if (otherObject instanceof Session) {
      Session other = (Session) otherObject;
      equal = (this == other)
          || ((this.sessionHandle_ == other.sessionHandle_) && this.token_
              .equals(other.token_));
    }

    return equal;
  }

  /**
   * The overriding of this method should ensure that the objects of this class work correctly in a
   * hashtable.
   * 
   * @return The hash code of this object. Gained from the sessionHandle.
   */
  public int hashCode() {
    return (int) sessionHandle_;
  }

  /**
   * Get the handle of this session.
   * 
   * @return The handle of this session.
   */
  public long getSessionHandle() {
    return sessionHandle_;
  }

  /**
   * Get information about this session.
   * 
   * @return An object providing information about this session.
   * @exception TokenException
   *              If getting the information failed.
   * 
   * @postconditions (result <> null)
   */
  public SessionInfo getSessionInfo() throws TokenException {
    CK_SESSION_INFO ckSessionInfo = pkcs11Module_.C_GetSessionInfo(sessionHandle_);

    return new SessionInfo(ckSessionInfo);
  }

  /**
   * Get the Module which this Session object operates with.
   * 
   * @return The module of this session.
   */
  public Module getModule() {
    return module_;
  }

  /**
   * Get the token that created this Session object.
   * 
   * @return The token of this session.
   */
  public Token getToken() {
    return token_;
  }

  /**
   * Get the current operation state. This state can be used later to restore the operation to
   * exactly this state.
   * 
   * @return The current operation state as a byte array.
   * @exception TokenException
   *              If saving the state fails or is not possible.
   * @see #setOperationState(byte[],Key,Key)
   * 
   * @postconditions (result <> null)
   */
  public byte[] getOperationState() throws TokenException {
    return pkcs11Module_.C_GetOperationState(sessionHandle_);
  }

  /**
   * Sets the operation state of this session to a previously saved one. This method may need the
   * key used during the saved operation to continue, because it may not be possible to save a key
   * into the state's byte array. Refer to the PKCS#11 standard for details on this function.
   * 
   * @param operationState
   *          The previously saved state as returned by getOperationState().
   * @param encryptionKey
   *          A encryption or decryption key, if a encryption or decryption operation was saved
   *          which should be continued, but the keys could not be saved.
   * @param authenticationKey
   *          A signing, verification of MAC key, if a signing, verification or MAC operation needs
   *          to be restored that could not save the key.
   * @exception TokenException
   *              If restoring the state fails.
   * @see #getOperationState()
   */
  public void setOperationState(byte[] operationState, Key encryptionKey,
      Key authenticationKey) throws TokenException {
    pkcs11Module_.C_SetOperationState(sessionHandle_, operationState,
        encryptionKey.getObjectHandle(), authenticationKey.getObjectHandle());
  }

  /**
   * Returns whether UTF8 encoding is set.
   * 
   * @return true, if UTF8 is used as character encoding for character array attributes and PINs.
   */
  public boolean isSetUtf8Encoding() {
    return useUtf8Encoding_;
  }

  /**
   * Logs in the user or the security officer to the session. Notice that all sessions of a token
   * have the same login state; i.e. if you login the user to one session all other open sessions of
   * this token get user rights.
   * 
   * @param userType
   *          UserType.SO for the security officer or UserType.USER to login the user.
   * @param pin
   *          The PIN. The security officer-PIN or the user-PIN depending on the userType parameter.
   * @exception TokenException
   *              If login fails.
   */
  public void login(boolean userType, char[] pin) throws TokenException {
    long lUserType = (userType == UserType.SO) ? PKCS11Constants.CKU_SO
        : PKCS11Constants.CKU_USER;
    pkcs11Module_.C_Login(sessionHandle_, lUserType, pin, useUtf8Encoding_);
  }

  /**
   * Logs out this session.
   * 
   * @exception TokenException
   *              If logging out the session fails.
   */
  public void logout() throws TokenException {
    pkcs11Module_.C_Logout(sessionHandle_);
  }

  /**
   * Create a new object on the token (or in the session). The application must provide a template
   * that holds enough information to create a certain object. For instance, if the application
   * wants to create a new DES key object it creates a new instance of the DESSecretKey class to
   * serve as a template. The application must set all attributes of this new object which are
   * required for the creation of such an object on the token. Then it passes this DESSecretKey
   * object to this method to create the object on the token. Example: <code>
   *   DESSecretKey desKeyTemplate = new DESSecretKey();
   *   // the key type is set by the DESSecretKey's constructor, so you need not do it
   *   desKeyTemplate.setValue(myDesKeyValueAs8BytesLongByteArray);
   *   desKeyTemplate.setToken(Boolean.TRUE);
   *   desKeyTemplate.setPrivate(Boolean.TRUE);
   *   desKeyTemplate.setEncrypt(Boolean.TRUE);
   *   desKeyTemplate.setDecrypt(Boolean.TRUE);
   *   ...
   *   DESSecretKey theCreatedDESKeyObject = (DESSecretKey) userSession.createObject(desKeyTemplate);
   * </code> Refer to the PKCS#11 standard to find out what attributes must be set for certain types
   * of objects to create them on the token.
   * 
   * @param templateObject
   *          The template object that holds all values that the new object on the token should
   *          contain. (this is not a java.lang.Object!)
   * @return A new PKCS#11 Object (this is not a java.lang.Object!) that serves holds all the
   *         (readable) attributes of the object on the token. In contrast to the templateObject,
   *         this object might have certain attributes set to token-dependent default-values.
   * @exception TokenException
   *              If the creation of the new object fails. If it fails, the no new object was
   *              created on the token.
   * @preconditions (templateObject <> null)
   * @postconditions (result <> null)
   */
  public Object createObject(Object templateObject) throws TokenException {
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(templateObject);
    long objectHandle = pkcs11Module_.C_CreateObject(sessionHandle_, ckAttributes,
        useUtf8Encoding_);

    return Object.getInstance(this, objectHandle);
  }

  /**
   * Copy an existing object. The source object and a template object are given. Any value set in
   * the template object will override the corresponding value from the source object, when the new
   * object ist created. See the PKCS#11 standard for details.
   * 
   * @param sourceObject
   *          The source object of the copy operation.
   * @param templateObject
   *          A template object which's attribute values are used for the new object; i.e. they have
   *          higher priority than the attribute values from the source object. May be null; in that
   *          case the new object is just a one-to-one copy of the sourceObject.
   * @return The new object that is created by copying the source object and setting attributes to
   *         the values given by the templateObject.
   * @exception TokenException
   *              If copying the object fails for some reason.
   * @preconditions (sourceObject <> null)
   * 
   */
  public Object copyObject(Object sourceObject, Object templateObject)
      throws TokenException {
    long sourceObjectHandle = sourceObject.getObjectHandle();
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(templateObject);
    long newObjectHandle = pkcs11Module_.C_CopyObject(sessionHandle_, sourceObjectHandle,
        ckAttributes, useUtf8Encoding_);

    return Object.getInstance(this, newObjectHandle);
  }

  /**
   * Gets all present attributes of the given template object an writes them to the object to update
   * on the token (or in the session). Both parameters may refer to the same Java object. This is
   * possible, because this method only needs the object handle of the objectToUpdate, and gets the
   * attributes to set from the template. This means, an application can get the object using
   * createObject of findObject, then modify attributes of this Java object and then call this
   * method passing this object as both parameters. This will update the object on the token to the
   * values as modified in the Java object.
   * 
   * @param objectToUpdate
   *          The attributes of this object get updated.
   * @param templateObject
   *          This methods gets all present attributes of this template object and set this
   *          attributes at the objectToUpdate.
   * @exception TokenException
   *              If updateing the attributes fails. All or no attributes are updated.
   * @preconditions (objectToUpdate <> null) and (template <> null)
   * 
   */
  public void setAttributeValues(Object objectToUpdate, Object templateObject)
      throws TokenException {
    long objectToUpdateHandle = objectToUpdate.getObjectHandle();
    CK_ATTRIBUTE[] ckAttributesTemplates = Object.getSetAttributes(templateObject);
    pkcs11Module_.C_SetAttributeValue(sessionHandle_, objectToUpdateHandle,
        ckAttributesTemplates, useUtf8Encoding_);
  }

  /**
   * Reads all the attributes of the given Object from the token and returns a new Object that
   * contains all these attributes. The given objectToRead and the returned Object are different
   * Java objects. This method just uses the object handle of the given object, it does not modify
   * anything in this object.
   * 
   * @param objectToRead
   *          The object to newly read from the token.
   * @return A new Object holding all attributes that this method just read from the token.
   * @exception TokenException
   *              If reading the attributes fails.
   * @preconditions (objectToRead <> null)
   * @postconditions (result <> null)
   */
  public Object getAttributeValues(Object objectToRead) throws TokenException {
    long objectHandle = objectToRead.getObjectHandle();

    return Object.getInstance(this, objectHandle);
  }

  /**
   * Destroy a certain object on the token (or in the session). Give the object that you want to
   * destroy. This method uses only the internal object handle of the given object to identify the
   * object.
   * 
   * @param object
   *          The object that should be destroyed.
   * @exception TokenException
   *              If the object could not be destroyed.
   * @preconditions (object <> null)
   * 
   */
  public void destroyObject(Object object) throws TokenException {
    long objectHandle = object.getObjectHandle();
    pkcs11Module_.C_DestroyObject(sessionHandle_, objectHandle);
  }

  /**
   * Get the size of the specified object in bytes. This size specifies how much memory the object
   * takes up on the token.
   * 
   * @param object
   *          The object to get the size for.
   * @return The object's size bytes.
   * @exception TokenException
   *              If determining the size fails.
   * @preconditions (object <> null)
   * 
   */
  public long getObjectSize(Object object) throws TokenException {
    long objectHandle = object.getObjectHandle();
    return pkcs11Module_.C_GetObjectSize(sessionHandle_, objectHandle);
  }

  /**
   * Initializes a find operations that provides means to find objects by passing a template object.
   * This method get all set attributes of the template object ans searches for all objects on the
   * token that match with these attributes.
   * 
   * @param templateObject
   *          The object that serves as a template for searching. If this object is null, the find
   *          operation will find all objects that this session can see. Notice, that only a user
   *          session will see private objects.
   * @exception TokenException
   *              If initializing the find operation fails.
   */
  public void findObjectsInit(Object templateObject) throws TokenException {
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(templateObject);
    pkcs11Module_.C_FindObjectsInit(sessionHandle_, ckAttributes, useUtf8Encoding_);
  }

  /**
   * Finds objects that match the template object passed to findObjectsInit. The application must
   * call findObjectsInit before calling this method. With maxObjectCount the application can
   * specifay how many objects to return at once; i.e. the application can get all found objects by
   * susequent calls to this method like maxObjectCount(1) until it receives an empty array (this
   * method never returns null!).
   * 
   * @param maxObjectCount
   *          Specifies how many objects to return with this call.
   * @return An array of found objects. The maximum size of this array is maxObjectCount, the
   *         minimum length is 0. Never returns null.
   * @exception TokenException
   *              A plain TokenException if something during PKCS11 FindObject went wrong, a
   *              TokenException with a nested TokenException if the Exception is raised during
   *              object parsing.
   * 
   * @postconditions (result <> null)
   */
  public Object[] findObjects(int maxObjectCount) throws TokenException {
    Vector foundObjects = new Vector();
    long[] objectHandles = pkcs11Module_.C_FindObjects(sessionHandle_, maxObjectCount);

    try {
      for (int i = 0; i < objectHandles.length; i++) {
        Object object = Object.getInstance(this, objectHandles[i]);
        foundObjects.addElement(object);
      }
      Object[] objectArray = new Object[foundObjects.size()];
      foundObjects.copyInto(objectArray);

      return objectArray;
    } catch (TokenException e) {
      // encapsulate exception to signal a cause other than C_FindObjects
      throw new TokenException(e);
    }
  }

  /**
   * Finalizes a find operation. The application must call this method to finalize a find operation
   * before attempting to start any other operation.
   * 
   * @exception TokenException
   *              If finalizing the current find operation was not possible.
   */
  public void findObjectsFinal() throws TokenException {
    pkcs11Module_.C_FindObjectsFinal(sessionHandle_);
  }

  /**
   * Initializes a new encryption operation. The application must call this method before calling
   * any other encrypt* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechansim to use for
   * encrpytion and the key for this oepration. The key must have set its encryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param key
   *          The decryption key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null) and (key <> null)
   * 
   */
  public void encryptInit(Mechanism mechanism, Key key) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_EncryptInit(sessionHandle_, ckMechanism, key.getObjectHandle(),
        useUtf8Encoding_);
  }

  /**
   * Encrypts the given data with the key and mechansim given to the encryptInit method. This method
   * finalizes the current encryption operation; i.e. the application need (and should) not call
   * encryptFinal() after this call. For encrypting multiple pices of data use encryptUpdate and
   * encryptFinal.
   * 
   * @param data
   *          The data to encrpyt.
   * @return The encrpyted data.
   * @exception TokenException
   *              If encrypting failed.
   * @preconditions (data <> null)
   * @postconditions (result <> null)
   */
  public byte[] encrypt(byte[] data) throws TokenException {
    return pkcs11Module_.C_Encrypt(sessionHandle_, data);
  }

  /**
   * This method can be used to encrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Encrypts the given data with the key and mechansim given to the
   * encryptInit method. The application must call encryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   * 
   * @param part
   *          The piece of data to encrpt.
   * @return The intermediate encryption result. May not be available. To get the final result call
   *         encryptFinal.
   * @exception TokenException
   *              If encrypting the data failed.
   * @preconditions (part <> null)
   * 
   */
  public byte[] encryptUpdate(byte[] part) throws TokenException {
    return pkcs11Module_.C_EncryptUpdate(sessionHandle_, part);
  }

  /**
   * This method finalizes an encrpytion operation and returns the final result. Use this method, if
   * you fed in the data using encryptUpdate. If you used the encrypt(byte[]) method, you need not
   * (and shall not) call this method, because encrypt(byte[]) finalizes the encryption itself.
   * 
   * @return The final result of the encryption; i.e. the encrypted data.
   * @exception TokenException
   *              If calculating the final result failed.
   * 
   * @postconditions (result <> null)
   */
  public byte[] encryptFinal() throws TokenException {
    return pkcs11Module_.C_EncryptFinal(sessionHandle_);
  }

  /**
   * Initializes a new decryption operation. The application must call this method before calling
   * any other decrypt* operation. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechansim to use for
   * decrpytion and the key for this oepration. The key must have set its decryption flag. For the
   * mechanism the application may use a constant defined in the Mechanism class. Notice that the
   * key and the mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.DES_CBC.
   * @param key
   *          The decryption key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null) and (key <> null)
   * 
   */
  public void decryptInit(Mechanism mechanism, Key key) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_DecryptInit(sessionHandle_, ckMechanism, key.getObjectHandle(),
        useUtf8Encoding_);
  }

  /**
   * Decrypts the given data with the key and mechansim given to the decryptInit method. This method
   * finalizes the current decryption operation; i.e. the application need (and should) not call
   * decryptFinal() after this call. For decrypting multiple pices of data use decryptUpdate and
   * decryptFinal.
   * 
   * @param data
   *          The data to decrpyt.
   * @return The decrpyted data.
   * @exception TokenException
   *              If decrypting failed.
   * @preconditions (data <> null)
   * @postconditions (result <> null)
   */
  public byte[] decrypt(byte[] data) throws TokenException {
    return pkcs11Module_.C_Decrypt(sessionHandle_, data);
  }

  /**
   * This method can be used to decrypt multiple pieces of data; e.g. buffer-size pieces when
   * reading the data from a stream. Decrypts the given data with the key and mechansim given to the
   * decryptInit method. The application must call decryptFinal to get the final result of the
   * encryption after feeding in all data using this method.
   * 
   * @param encryptedPart
   *          The piece of data to decrpt.
   * @return The intermediate decryption result. May not be available. To get the final result call
   *         decryptFinal.
   * @exception TokenException
   *              If decrypting the data failed.
   * @preconditions (encryptedPart <> null)
   * 
   */
  public byte[] decryptUpdate(byte[] encryptedPart) throws TokenException {
    return pkcs11Module_.C_DecryptUpdate(sessionHandle_, encryptedPart);
  }

  /**
   * This method finalizes a decrpytion operation and returns the final result. Use this method, if
   * you fed in the data using decryptUpdate. If you used the decrypt(byte[]) method, you need not
   * (and shall not) call this method, because decrypt(byte[]) finalizes the decryption itself.
   * 
   * @return The final result of the decryption; i.e. the decrypted data.
   * @exception TokenException
   *              If calculating the final result failed.
   * 
   * @postconditions (result <> null)
   */
  public byte[] decryptFinal() throws TokenException {
    return pkcs11Module_.C_DecryptFinal(sessionHandle_);
  }

  /**
   * Initializes a new digesting operation. The application must call this method before calling any
   * other digest* operation. Before initializing a new operation, any currently pending operation
   * must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechansim to use for
   * digesting for this oepration. For the mechanism the application may use a constant defined in
   * the Mechanism class.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.SHA_1.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null)
   * 
   */
  public void digestInit(Mechanism mechanism) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_DigestInit(sessionHandle_, ckMechanism, useUtf8Encoding_);
  }

  /**
   * Digests the given data with the mechansim given to the digestInit method. This method finalizes
   * the current digesting operation; i.e. the application need (and should) not call digestFinal()
   * after this call. For digesting multiple pices of data use digestUpdate and digestFinal.
   * 
   * @param data
   *          The data to digest.
   * @return The digested data.
   * @exception TokenException
   *              If digesting the data failed.
   * @preconditions (data <> null)
   * @postconditions (result <> null)
   */
  public byte[] digest(byte[] data) throws TokenException {
    return pkcs11Module_.C_Digest(sessionHandle_, data);
  }

  /**
   * This method can be used to digest multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Digests the given data with the mechansim given to the digestInit
   * method. The application must call digestFinal to get the final result of the digesting after
   * feeding in all data using this method.
   * 
   * @param part
   *          The piece of data to digest.
   * @exception TokenException
   *              If digesting the data failed.
   * @preconditions (part <> null)
   * 
   */
  public void digestUpdate(byte[] part) throws TokenException {
    pkcs11Module_.C_DigestUpdate(sessionHandle_, part);
  }

  /**
   * This method is similar to digestUpdate and can be combined with it during one digesting
   * operation. This method digests the value of the given secret key.
   * 
   * @param key
   *          The key to digest the value of.
   * @exception TokenException
   *              If digesting the key failed.
   * @preconditions (key <> null)
   * 
   */
  public void digestKey(SecretKey key) throws TokenException {
    pkcs11Module_.C_DigestKey(sessionHandle_, key.getObjectHandle());
  }

  /**
   * This method finalizes a digesting operation and returns the final result. Use this method, if
   * you fed in the data using digestUpdate and/or digestKey. If you used the digest(byte[]) method,
   * you need not (and shall not) call this method, because digest(byte[]) finalizes the digesting
   * itself.
   * 
   * @return The final result of the digesting; i.e. the message digest.
   * @exception TokenException
   *              If calculating the final message digest failed.
   * 
   * @postconditions (result <> null)
   */
  public byte[] digestFinal() throws TokenException {
    return pkcs11Module_.C_DigestFinal(sessionHandle_);
  }

  /**
   * Initializes a new signing operation. Use it for signatures and MACs. The application must call
   * this method before calling any other sign* operation. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). There are exceptions for dual-function operations. This method requires the
   * mechansim to use for signing and the key for this oepration. The key must have set its sign
   * flag. For the mechanism the application may use a constant defined in the Mechanism class.
   * Notice that the key and the mechanism must be compatible; i.e. you cannot use a DES key with
   * the RSA mechanism.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param key
   *          The signing key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null) and (key <> null)
   * 
   */
  public void signInit(Mechanism mechanism, Key key) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_SignInit(sessionHandle_, ckMechanism, key.getObjectHandle(),
        useUtf8Encoding_);
  }

  /**
   * Signs the given data with the key and mechansim given to the signInit method. This method
   * finalizes the current signing operation; i.e. the application need (and should) not call
   * signFinal() after this call. For signing multiple pices of data use signUpdate and signFinal.
   * 
   * @param data
   *          The data to sign.
   * @return The signed data.
   * @exception TokenException
   *              If signing the data failed.
   * @preconditions (data <> null)
   * @postconditions (result <> null)
   */
  public byte[] sign(byte[] data) throws TokenException {
    return pkcs11Module_.C_Sign(sessionHandle_, data);
  }

  /**
   * This method can be used to sign multiple pieces of data; e.g. buffer-size pieces when reading
   * the data from a stream. Signs the given data with the mechansim given to the signInit method.
   * The application must call signFinal to get the final result of the signing after feeding in all
   * data using this method.
   * 
   * @param part
   *          The piece of data to sign.
   * @exception TokenException
   *              If signing the data failed.
   * @preconditions (part <> null)
   * 
   */
  public void signUpdate(byte[] part) throws TokenException {
    pkcs11Module_.C_SignUpdate(sessionHandle_, part);
  }

  /**
   * This method finalizes a signing operation and returns the final result. Use this method, if you
   * fed in the data using signUpdate. If you used the sign(byte[]) method, you need not (and shall
   * not) call this method, because sign(byte[]) finalizes the signing operation itself.
   * 
   * @return The final result of the signing operation; i.e. the signature value.
   * @exception TokenException
   *              If calculating the final signature value failed.
   * 
   * @postconditions (result <> null)
   */
  public byte[] signFinal() throws TokenException {
    return pkcs11Module_.C_SignFinal(sessionHandle_);
  }

  /**
   * Initializes a new signing operation for signing with recovery. The application must call this
   * method before calling signRecover. Before initializing a new operation, any currently pending
   * operation must be finalized using the appropriate *Final method (e.g. digestFinal()). There are
   * exceptions for dual-function operations. This method requires the mechansim to use for signing
   * and the key for this oepration. The key must have set its sign-recover flag. For the mechanism
   * the application may use a constant defined in the Mechanism class. Notice that the key and the
   * mechanism must be compatible; i.e. you cannot use a DES key with the RSA mechanism.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param key
   *          The signing key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null) and (key <> null)
   * 
   */
  public void signRecoverInit(Mechanism mechanism, Key key) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_SignRecoverInit(sessionHandle_, ckMechanism, key.getObjectHandle(),
        useUtf8Encoding_);
  }

  /**
   * Signs the given data with the key and mechansim given to the signRecoverInit method. This
   * method finalizes the current sign-recover operation; there is no equivalent method to
   * signUpdate for signing with recovery.
   * 
   * @param data
   *          The data to sign.
   * @return The signed data.
   * @exception TokenException
   *              If signing the data failed.
   * @preconditions (data <> null)
   * @postconditions (result <> null)
   */
  public byte[] signRecover(byte[] data) throws TokenException {
    return pkcs11Module_.C_SignRecover(sessionHandle_, data);
  }

  /**
   * Initializes a new verification operation. You can use it for verifying signatures and MACs. The
   * application must call this method before calling any other verify* operation. Before
   * initializing a new operation, any currently pending operation must be finalized using the
   * appropriate *Final method (e.g. digestFinal()). There are exceptions for dual-function
   * operations. This method requires the mechansim to use for verification and the key for this
   * oepration. The key must have set its verify flag. For the mechanism the application may use a
   * constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_PKCS.
   * @param key
   *          The verification key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null) and (key <> null)
   * 
   */
  public void verifyInit(Mechanism mechanism, Key key) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_VerifyInit(sessionHandle_, ckMechanism, key.getObjectHandle(),
        useUtf8Encoding_);
  }

  /**
   * Verifies the given signature against the given data with the key and mechansim given to the
   * verifyInit method. This method finalizes the current verification operation; i.e. the
   * application need (and should) not call verifyFinal() after this call. For verifying with
   * multiple pices of data use verifyUpdate and verifyFinal. This method throws an exception, if
   * the verification of the signature fails.
   * 
   * @param data
   *          The data that was signed.
   * @param signature
   *          The signature or MAC to verify.
   * @exception TokenException
   *              If verifying the signature fails. This is also the case, if the signature is
   *              forged.
   * @preconditions (data <> null) and (signature <> null)
   * 
   */
  public void verify(byte[] data, byte[] signature) throws TokenException {
    pkcs11Module_.C_Verify(sessionHandle_, data, signature);
  }

  /**
   * This method can be used to verify a signature with multiple pieces of data; e.g. buffer-size
   * pieces when reading the data from a stream. To verify the signature or MAC call verifyFinal
   * after feeding in all data using this method.
   * 
   * @param part
   *          The piece of data to verify against.
   * @exception TokenException
   *              If verifying (e.g. digesting) the data failed.
   * @preconditions (part <> null)
   * 
   */
  public void verifyUpdate(byte[] part) throws TokenException {
    pkcs11Module_.C_VerifyUpdate(sessionHandle_, part);
  }

  /**
   * This method finalizes a verification operation. Use this method, if you fed in the data using
   * verifyUpdate. If you used the verify(byte[]) method, you need not (and shall not) call this
   * method, because verify(byte[]) finalizes the verification operation itself. If this method
   * verified the signature successfully, it returns normally. If the verification of the signature
   * fails, e.g. if the signature was forged or the data was modified, this method throws an
   * exception.
   * 
   * @param signature
   *          The signature value.
   * @exception TokenException
   *              If verifying the signature fails. This is also the case, if the signature is
   *              forged.
   * 
   * @postconditions (result <> null)
   */
  public void verifyFinal(byte[] signature) throws TokenException {
    pkcs11Module_.C_VerifyFinal(sessionHandle_, signature);
  }

  /**
   * Initializes a new verification operation for verification with data recovery. The application
   * must call this method before calling verifyRecover. Before initializing a new operation, any
   * currently pending operation must be finalized using the appropriate *Final method (e.g.
   * digestFinal()). This method requires the mechansim to use for verification and the key for this
   * oepration. The key must have set its verify-recover flag. For the mechanism the application may
   * use a constant defined in the Mechanism class. Notice that the key and the mechanism must be
   * compatible; i.e. you cannot use a DES key with the RSA mechanism.
   * 
   * @param mechanism
   *          The mechanism to use; e.g. Mechanism.RSA_9796.
   * @param key
   *          The verification key to use.
   * @exception TokenException
   *              If initializing this operation failed.
   * @preconditions (mechansim <> null) and (key <> null)
   * 
   */
  public void verifyRecoverInit(Mechanism mechanism, Key key) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    pkcs11Module_.C_VerifyRecoverInit(sessionHandle_, ckMechanism, key.getObjectHandle(),
        useUtf8Encoding_);
  }

  /**
   * Signs the given data with the key and mechansim given to the signRecoverInit method. This
   * method finalizes the current sign-recover operation; there is no equivalent method to
   * signUpdate for signing with recovery.
   * 
   * @param signature
   *          The data to sign.
   * @return The signed data.
   * @exception TokenException
   *              If signing the data failed.
   * @preconditions (data <> null)
   * @postconditions (result <> null)
   */
  public byte[] verifyRecover(byte[] signature) throws TokenException {
    return pkcs11Module_.C_VerifyRecover(sessionHandle_, signature);
  }

  /**
   * Dual-function. Continues a multipart dual digest and encryption operation. This method call can
   * also be combined with calls to digestUpdate, digestKey and encryptUpdate. Call digestFinal and
   * encryptFinal to get the final results.
   * 
   * @param part
   *          The piece of data to digest and encrypt.
   * @return The intermediate result of the encryption.
   * @exception TokenException
   *              If digesting or encrypting the data failed.
   * @preconditions (part <> null)
   * 
   */
  public byte[] digestEncryptedUpdate(byte[] part) throws TokenException {
    return pkcs11Module_.C_DigestEncryptUpdate(sessionHandle_, part);
  }

  /**
   * Dual-function. Continues a multipart dual decrypt and digest operation. This method call can
   * also be combined with calls to digestUpdate, digestKey and decryptUpdate. It is the recovered
   * plaintext that gets digested in this method call, not the given encryptedPart. Call digestFinal
   * and decryptFinal to get the final results.
   * 
   * @param part
   *          The piece of data to decrypt and digest.
   * @return The intermediate result of the decryption; the decrypted data.
   * @exception TokenException
   *              If decrypting or digesting the data failed.
   * @preconditions (part <> null)
   * 
   */
  public byte[] decryptDigestUpdate(byte[] part) throws TokenException {
    return pkcs11Module_.C_DecryptDigestUpdate(sessionHandle_, part);
  }

  /**
   * Dual-function. Continues a multipart dual sign and encrypt operation. Calls to this method can
   * also be combined with calls to signUpdate and encryptUpdate. Call signFinal and encryptFinal to
   * get the final results.
   * 
   * @param part
   *          The piece of data to sign and encrypt.
   * @return The intermediate result of the encryption; the encrypted data.
   * @exception TokenException
   *              If signing or encrypting the data failed.
   * @preconditions (part <> null)
   * 
   */
  public byte[] signEncryptUpdate(byte[] part) throws TokenException {
    return pkcs11Module_.C_SignEncryptUpdate(sessionHandle_, part);
  }

  /**
   * Dual-function. Continues a multipart dual decrypt and verify operation. This method call can
   * also be combined with calls to decryptUpdate and verifyUpdate. It is the recovered plaintext
   * that gets verified in this method call, not the given encryptedPart. Call decryptFinal and
   * verifyFinal to get the final results.
   * 
   * @param encryptedPart
   *          The piece of data to decrypt and verify.
   * @return The intermediate result of the decryption; the decrypted data.
   * @exception TokenException
   *              If decrypting or verifying the data failed.
   * @preconditions (encryptedPart <> null)
   * 
   */
  public byte[] decryptVerifyUpdate(byte[] encryptedPart) throws TokenException {
    return pkcs11Module_.C_DecryptVerifyUpdate(sessionHandle_, encryptedPart);
  }

  /**
   * Generate a new secret key or a set of domain parameters. It uses the set attributes of the
   * template for setting the attributes of the new key object. As mechanism the application can use
   * a constant of the Mechanism class.
   * 
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.DES to generate a DES key.
   * @param template
   *          The template for the new key or domain parameters; e.g. a DESSecretKey object which
   *          has set certain attributes.
   * @return The newly generated secret key or domain parameters.
   * @exception TokenException
   *              If generating a new secert key or domain parameters failed.
   * 
   * @postconditions (result instanceof SecretKey) or (result instanceof DomainParameters)
   */
  public Object generateKey(Mechanism mechanism, Object template) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(template);

    long objectHandle = pkcs11Module_.C_GenerateKey(sessionHandle_, ckMechanism,
        ckAttributes, useUtf8Encoding_);

    return Object.getInstance(this, objectHandle);
  }

  /**
   * Generate a new public key - private key key-pair and use the set attributes of the template
   * objects for setting the attributes of the new public key and private key objects. As mechanism
   * the application can use a constant of the Mechanism class.
   * 
   * @param mechanism
   *          The mechanism to generate a key for; e.g. Mechanism.RSA to generate a new RSA
   *          key-pair.
   * @param publicKeyTemplate
   *          The template for the new public key part; e.g. a RSAPublicKey object which has set
   *          certain attributes (e.g. public exponent and verify).
   * @param privateKeyTemplate
   *          The template for the new private key part; e.g. a RSAPrivateKey object which has set
   *          certain attributes (e.g. sign and decrypt).
   * @return The newly generated key-pair.
   * @exception TokenException
   *              If generating a new key-pair failed.
   */
  public KeyPair generateKeyPair(Mechanism mechanism, Object publicKeyTemplate,
      Object privateKeyTemplate) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;
    CK_ATTRIBUTE[] ckPublicKeyAttributes = Object.getSetAttributes(publicKeyTemplate);
    CK_ATTRIBUTE[] ckPrivateKeyAttributes = Object.getSetAttributes(privateKeyTemplate);

    long[] objectHandles = pkcs11Module_.C_GenerateKeyPair(sessionHandle_, ckMechanism,
        ckPublicKeyAttributes, ckPrivateKeyAttributes, useUtf8Encoding_);

    PublicKey publicKey = (PublicKey) Object.getInstance(this, objectHandles[0]);
    PrivateKey privateKey = (PrivateKey) Object.getInstance(this, objectHandles[1]);

    return new KeyPair(publicKey, privateKey);
  }

  /**
   * Wraps (encrypts) the given key with the wrapping key using the given mechanism.
   * 
   * @param mechanism
   *          The mechanism to use for wrapping the key.
   * @param wrappingKey
   *          The key to use for wrapping (encrypting).
   * @param key
   *          The key to wrap (encrypt).
   * @return The wrapped key as byte array.
   * @exception TokenException
   *              If wrapping the key failed.
   * @preconditions (mechanism <> null) and (wrappingKey <> null) and (key <> null)
   * @postconditions (result <> null)
   */
  public byte[] wrapKey(Mechanism mechanism, Key wrappingKey, Key key)
      throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;

    return pkcs11Module_.C_WrapKey(sessionHandle_, ckMechanism,
        wrappingKey.getObjectHandle(), key.getObjectHandle(), useUtf8Encoding_);
  }

  /**
   * Unwraps (decrypts) the given encrypted key with the unwrapping key using the given mechanism.
   * The application can also pass a template key to set certain attributes of the unwrapped key.
   * This creates a key object after unwrapping the key and returns an object representing this key.
   * 
   * @param mechanism
   *          The mechanism to use for unwrapping the key.
   * @param unwrappingKey
   *          The key to use for unwrapping (decrypting).
   * @param wrappedKey
   *          The encrypted key to unwrap (decrypt).
   * @param keyTemplate
   *          The template for creating the new key object.
   * @return A key object representing the newly created key object.
   * @exception TokenException
   *              If unwrapping the key or creating a new key object failed.
   * @preconditions (mechanism <> null) and (unwrappingKey <> null) and (wrappedKey <> null)
   * @postconditions (result <> null)
   */
  public Key unwrapKey(Mechanism mechanism, Key unwrappingKey, byte[] wrappedKey,
      Object keyTemplate) throws TokenException {
    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(keyTemplate);

    long objectHandle = pkcs11Module_.C_UnwrapKey(sessionHandle_, ckMechanism,
        unwrappingKey.getObjectHandle(), wrappedKey, ckAttributes, useUtf8Encoding_);

    return (Key) Object.getInstance(this, objectHandle);
  }

  /**
   * Derives a new key from a specified base key unsing the given mechanism. After deriving a new
   * key from the base key, a new key object is created and a representation of it is returned. The
   * application can provide a template key to set certain attributes of the new key object.
   * 
   * @param mechanism
   *          The mechanism to use for deriving the new key from the base key.
   * @param baseKey
   *          The key to use as base for derivation.
   * @param template
   *          The template for creating the new key object.
   * @return A key object representing the newly derived (created) key object or null, if the used
   *         mechanism uses other means to return its values; e.g. the CKM_SSL3_KEY_AND_MAC_DERIVE
   *         mechanism.
   * @exception TokenException
   *              If deriving the key or creating a new key object failed.
   * @preconditions (mechanism <> null) and (baseKey <> null)
   * 
   */
  public Key deriveKey(Mechanism mechanism, Key baseKey, Key template)
      throws TokenException {
    Key derivedKey = null;

    CK_MECHANISM ckMechanism = new CK_MECHANISM();
    ckMechanism.mechanism = mechanism.getMechanismCode();
    Parameters parameters = mechanism.getParameters();
    ckMechanism.pParameter = (parameters != null) ? parameters.getPKCS11ParamsObject()
        : null;
    CK_ATTRIBUTE[] ckAttributes = Object.getSetAttributes(template);

    long objectHandle = pkcs11Module_.C_DeriveKey(sessionHandle_, ckMechanism,
        baseKey.getObjectHandle(), ckAttributes, useUtf8Encoding_);

    /*
     * for certain mechanisms we must copy back the returned values the the parameters object of the
     * given mechanism
     */
    if ((ckMechanism.mechanism == PKCS11Constants.CKM_SSL3_MASTER_KEY_DERIVE || ckMechanism.mechanism == PKCS11Constants.CKM_TLS_MASTER_KEY_DERIVE)
        && (parameters instanceof SSL3MasterKeyDeriveParameters)) {
      /*
       * The SSL3MasterKeyDeriveParameters object need special handling due to their deeper nesting
       * of their data structure, which needs to be copied back to get all the results.
       */
      // set the returned client version
      ((SSL3MasterKeyDeriveParameters) parameters).getVersion().setPKCS11ParamsObject(
          ((CK_SSL3_MASTER_KEY_DERIVE_PARAMS) (ckMechanism.pParameter)).pVersion);
      derivedKey = (Key) Object.getInstance(this, objectHandle);
    } else if ((ckMechanism.mechanism == PKCS11Constants.CKM_SSL3_KEY_AND_MAC_DERIVE || ckMechanism.mechanism == PKCS11Constants.CKM_TLS_KEY_AND_MAC_DERIVE)
        && (parameters instanceof SSL3KeyMaterialParameters)) {
      /*
       * The SSL3KeyMaterialParameters object need special handling due to their deeper nesting of
       * their data structure, which needs to be copied back to get all the results.
       */
      // set the returned secret keys and IVs
      ((SSL3KeyMaterialParameters) parameters).getReturnedKeyMaterial()
          .setPKCS11ParamsObject(
              ((CK_SSL3_KEY_MAT_PARAMS) (ckMechanism.pParameter)).pReturnedKeyMaterial,
              this);
      /*
       * this mechanism returns its keys and values through the parameters object of the mechanism,
       * but it does not return a key
       */
      derivedKey = null;
    } else {
      derivedKey = (Key) Object.getInstance(this, objectHandle);
    }

    return derivedKey;
  }

  /**
   * Mixes additional seeding material into the random number generator.
   * 
   * @param seed
   *          The seed bytes to mix in.
   * @exception TokenException
   *              If mixing in the seed failed.
   * @preconditions (seed <> null)
   * 
   */
  public void seedRandom(byte[] seed) throws TokenException {
    pkcs11Module_.C_SeedRandom(sessionHandle_, seed);
  }

  /**
   * Generates a certain number of random bytes.
   * 
   * @param numberOfBytesToGenerate
   *          The number of random bytes to generate.
   * @return An array of random bytes with length numberOfBytesToGenerate.
   * @exception TokenException
   *              If generating random bytes failed.
   * @preconditions (numberOfBytesToGenerate >= 0)
   * @postconditions (result <> null) and (result.length == numberOfBytesToGenerate)
   */
  public byte[] generateRandom(int numberOfBytesToGenerate) throws TokenException {
    byte[] randomBytesBuffer = new byte[numberOfBytesToGenerate];
    pkcs11Module_.C_GenerateRandom(sessionHandle_, randomBytesBuffer); // fill
                                                                       // the
                                                                       // buffer
                                                                       // with
                                                                       // random
                                                                       // bytes

    return randomBytesBuffer;
  }

  /**
   * Legacy function that will normally throw an PKCS11Exception with the error-code
   * PKCS11Constants.CKR_FUNCTION_NOT_PARALLEL.
   * 
   * @exception TokenException
   *              Throws always an PKCS11Excption.
   */
  public void getFunctionStatus() throws TokenException {
    pkcs11Module_.C_GetFunctionStatus(sessionHandle_);
  }

  /**
   * Legacy function that will normally throw an PKCS11Exception with the error-code
   * PKCS11Constants.CKR_FUNCTION_NOT_PARALLEL.
   * 
   * @exception TokenException
   *              Throws always an PKCS11Excption.
   */
  public void cancelFunction() throws TokenException {
    pkcs11Module_.C_CancelFunction(sessionHandle_);
  }

  /**
   * Returns the string representation of this object.
   * 
   * @return the string representation of this object
   */
  public String toString() {
    StringBuffer buffer = new StringBuffer();

    buffer.append("Session Handle: ");
    buffer.append("0x");
    buffer.append(Functions.toHexString(sessionHandle_));
    buffer.append(Constants.NEWLINE);

    buffer.append("Token: ");
    buffer.append(token_.toString());

    return buffer.toString();
  }

}
