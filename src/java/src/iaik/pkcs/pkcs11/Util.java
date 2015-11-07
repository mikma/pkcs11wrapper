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

import iaik.pkcs.pkcs11.wrapper.CK_ATTRIBUTE;
import iaik.pkcs.pkcs11.wrapper.CK_DATE;

import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.util.Vector;

/**
 * A class consisting of static methods only which provide certain static piecec of code that are
 * used frequently in this project.
 * 
 * @author Karl Scheibelhofer
 * @version 1.0
 * 
 */
public class Util {

  /**
   * Parse a time character array as defined in PKCS#11 and return is as a Date object.
   * 
   * @param timeChars
   *          A time encoded as character array as specified in PKCS#11.
   * @return A Date object set to the time indicated in the given char-array. null, if the given
   *         char array is null or the format is wrong.
   */
  public static Date parseTime(char[] timeChars) {
    Date time = null;

    if ((timeChars != null) && timeChars.length > 2) {
      String timeString = new String(timeChars, 0, timeChars.length - 2);
      try {
        SimpleDateFormat utc = new SimpleDateFormat("yyyyMMddhhmmss");
        utc.setTimeZone(TimeZone.getTimeZone("UTC"));
        time = utc.parse(timeString);
        // time = new SimpleDateFormat("yyyyMMddhhmmss").parse(timeString);
      } catch (ParseException ex) { /* nothing else to be done */
      }
    }

    return time;
  }

  /**
   * Convert the given CK_DATE object to a Date object.
   * 
   * @param ckDate
   *          The object providing the date information.
   * @return The new Date object or null, if the given ckDate is null.
   */
  public static Date convertToDate(CK_DATE ckDate) {
    Date date = null;

    if (ckDate != null) {
      int year = Integer.parseInt(new String(ckDate.year));
      int month = Integer.parseInt(new String(ckDate.month));
      int day = Integer.parseInt(new String(ckDate.day));
      Calendar calendar = new GregorianCalendar(); // poor performance, consider alternatives
      calendar.set(year, Calendar.JANUARY + (month - 1), day); // calendar starts months with 0
      date = calendar.getTime();
    }

    return date;
  }

  /**
   * Convert the given Date object to a CK_DATE object.
   * 
   * @param date
   *          The object providing the date information.
   * @return The new CK_DATE object or null, if the given date is null.
   */
  public static CK_DATE convertToCkDate(Date date) {
    CK_DATE ckDate = null;

    if (date != null) {
      Calendar calendar = new GregorianCalendar(); // poor memory/performance behavior, consider
                                                   // alternatives
      calendar.setTime(date);
      int year = calendar.get(Calendar.YEAR);
      int month = calendar.get(Calendar.MONTH) + 1; // month counting starts with zero
      int day = calendar.get(Calendar.DAY_OF_MONTH);
      ckDate = new CK_DATE();
      ckDate.year = toCharArray(year, 4);
      ckDate.month = toCharArray(month, 2);
      ckDate.day = toCharArray(day, 2);
    }

    return ckDate;
  }

  /**
   * Converts the given number into a char-array. If the length of the array is shorter than the
   * required exact length, the array is padded with leading '0' chars. If the array is longer than
   * the wanted length the most significant digits are cut off until the array has the exact length.
   * 
   * @param number
   *          The number to convert to a char array.
   * @param exactArrayLength
   *          The exact length of the returned array.
   * @return The numebr as char array, one char for each decimal digit.
   * @preconditions (exactArrayLength >= 0)
   * @postconditions (result <> null) and (result.length == exactArrayLength)
   */
  public static char[] toCharArray(int number, int exactArrayLength) {
    char[] charArray = null;

    String numberString = Integer.toString(number);
    char[] numberChars = numberString.toCharArray();

    if (numberChars.length > exactArrayLength) {
      // cut off digits beginning at most significant digit
      charArray = new char[exactArrayLength];
      for (int i = 0; i < charArray.length; i++) {
        charArray[i] = numberChars[i];
      }
    } else if (numberChars.length < exactArrayLength) {
      // pad with '0' leading chars
      charArray = new char[exactArrayLength];
      int offset = exactArrayLength - numberChars.length;
      for (int i = 0; i < charArray.length; i++) {
        charArray[i] = (i < offset) ? '0' : numberChars[i - offset];
      }
    } else {
      charArray = numberChars;
    }

    return charArray;
  }

  /**
   * Converts the given string to a char-array of exactly the given length. If the given string is
   * short than the wanted length, then the array is padded with trailing padding chars. If the
   * string is longer, the last character are cut off that the string has the wanted size.
   * 
   * @param string
   *          The string to convert.
   * @param exactArrayLength
   *          The length of the retirned char-array.
   * @param paddingChar
   *          The character to use for padding, if necessary.
   * @return The string as char array, padded or cut off, if necessary. The array will have length
   *         exactArrayLength. null, if the given string is null.
   * @preconditions (exactArrayLength >= 0)
   * @postconditions (result == null) or (result <> null) and (result.length == exactArrayLength)
   */
  public static char[] toPaddedCharArray(String string, int exactArrayLength,
      char paddingChar) {
    char[] charArray = null;

    if (string != null) {
      int stringLength = string.length();
      charArray = new char[exactArrayLength];
      string.getChars(0, Math.min(stringLength, exactArrayLength), charArray, 0);
      for (int i = stringLength; i < charArray.length; i++) { // fill the rest of the array with
                                                              // padding char
        charArray[i] = paddingChar;
      }
    }

    return charArray;
  }

  /**
   * Convert a BigInteger to a byte-array, but treat the byte-array given from the BigInteger as
   * unsigned and removing any leading zero bytes; e.g. a 1024 bit integer with its highest bit set
   * will result in an 128 byte array.
   * 
   * @param bigInteger
   *          The BigInteger to convert.
   * @return The byte-array representation of the BigInterger without signum-bit. null, if the
   *         BigInteger is null.
   */
  public static byte[] unsignedBigIntergerToByteArray(BigInteger bigInteger) {
    if (bigInteger == null) {
      return null;
    }
    byte[] integerBytes = bigInteger.toByteArray();
    byte[] unsignedIntegerBytes;
    if ((integerBytes.length > 0) && (integerBytes[0] == 0x00)) {
      unsignedIntegerBytes = new byte[integerBytes.length - 1];
      for (int i = 0; i < unsignedIntegerBytes.length; i++) {
        unsignedIntegerBytes[i] = integerBytes[i + 1];
      }
    } else {
      unsignedIntegerBytes = integerBytes;
    }

    return unsignedIntegerBytes;
  }

  /**
   * Converts the given vector into an array of CK_ATTRIBUTE elements. Elements not of type
   * CK_ATTRIBUTE will not be present in the resulting array and be set to null.
   * 
   * @param attributes
   *          The vector which contains the attributes.
   * @return The array of the attributes.
   * 
   * @postconditions (attributes <> null) implies (result.length == attributes.size())
   */
  public static CK_ATTRIBUTE[] convertAttributesVectorToArray(Vector attributes) {
    if (attributes == null) {
      return null;
    }
    int numberOfAttributes = attributes.size();
    CK_ATTRIBUTE[] attributeArray = new CK_ATTRIBUTE[numberOfAttributes];
    Object currentVectorEntry;

    for (int i = 0; i < numberOfAttributes; i++) {
      currentVectorEntry = attributes.elementAt(i);
      attributeArray[i] = (currentVectorEntry instanceof CK_ATTRIBUTE) ? (CK_ATTRIBUTE) currentVectorEntry
          : null;
    }

    return attributeArray;
  }

}
