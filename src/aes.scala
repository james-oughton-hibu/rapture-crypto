/**********************************************************************************************\
* Rapture Crypto Library                                                                       *
* Version 0.9.0                                                                                *
*                                                                                              *
* The primary distribution site is                                                             *
*                                                                                              *
*   http://rapture.io/                                                                         *
*                                                                                              *
* Copyright 2010-2014 Jon Pretty, Propensive Ltd.                                              *
*                                                                                              *
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file    *
* except in compliance with the License. You may obtain a copy of the License at               *
*                                                                                              *
*   http://www.apache.org/licenses/LICENSE-2.0                                                 *
*                                                                                              *
* Unless required by applicable law or agreed to in writing, software distributed under the    *
* License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,    *
* either express or implied. See the License for the specific language governing permissions   *
* and limitations under the License.                                                           *
\**********************************************************************************************/
package rapture.crypto
import rapture.core._

import java.security._
import javax.crypto._
import javax.crypto.spec._
import java.util._

import digests._

trait CryptoMethods extends RtsGroup

/** Provides a simple interface for AES encryption with SHA-256 digest
  * verification. This class is stateless. */
abstract class AesEncryption {

  /** Must be 16, 24 or 32 bytes long. */
  protected def secretKey: Array[Byte]

  private val keySpec = new SecretKeySpec(secretKey, "AES")

  def encrypt(clearText: Array[Byte], iv: Array[Byte] = null): Array[Byte] = {
    
    val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
    
    if(iv == null) cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec)
    else cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv))
    
    val digest = Hash.digest[Sha256](clearText).bytes
    val paddedLength = (clearText.length >> 4) + 1 << 4
    val cipherText = new Array[Byte](paddedLength + (if(iv == null) 48 else 0))
    
    if(iv == null) {
      Array.copy(cipher.getIV, 0, cipherText, 0, 16)
      cipher.update(digest, 0, 32, cipherText, 16)
    }
    cipher.doFinal(clearText, 0, clearText.length, cipherText, if(iv == null) 48 else 0)
    
    cipherText
  }

  def decrypt(cipherText: Array[Byte], iv: Array[Byte] = null)(implicit rts: Rts[CryptoMethods]):
      rts.Wrap[Array[Byte], DecryptionException] = rts.wrap {
    if(iv == null && cipherText.length < 48) throw DecryptionException()
      
    val cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding")
    val ips = if(iv == null) new IvParameterSpec(cipherText, 0, 16) else new IvParameterSpec(iv)
    
    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, ips)
    
    val n = if(iv == null) 64 else 0
    
    val digest1 = if(iv == null) cipher.update(cipherText, 16, 48) else Array[Byte]()
    val clearText = cipher.doFinal(cipherText, n, cipherText.length - n)
    
    if(iv == null) {
      val digest2 = Hash.digest[Sha256](clearText).bytes
      var i = 0
      var r = true
    
      
      while(i < 32) {
        if(digest1(i) != digest2(i)) r = false
        i += 1
      }

      if(!r) {
        Arrays.fill(digest1, 0.toByte)
        Arrays.fill(digest2, 0.toByte)
        Arrays.fill(clearText, 0.toByte)
        throw DecryptionException()
      }
    }
    
    clearText
  }

  def apply(clearText: Array[Byte]): Array[Byte] = encrypt(clearText)
  
  def unapply(cipherText: Array[Byte]): Option[Array[Byte]] =
    try Some(decrypt(cipherText)(strategy.throwExceptions)) catch { case DecryptionException() => None }
}

class Base64StringEncryption(sk: String) {
  
  private val _secretKey = sk.getBytes("ASCII")
  
  require(_secretKey.length == 32 || _secretKey.length == 24 || _secretKey.length == 16)

  private val aesEnc = new AesEncryption { def secretKey = _secretKey }

  protected val base64: Base64Codec = Base64

  def encrypt(string: String): String =
    base64.encode(aesEnc.encrypt(string.getBytes("UTF-8"))).mkString
  
  def decrypt(string: String)(implicit rts: Rts[CryptoMethods]): rts.Wrap[String, DecryptionException] = rts.wrap {
    new String(aesEnc.decrypt(base64.decode(string)(raw))(raw), "UTF-8")
  }
}

/** Shared implementation for AesInts and AesLongs. */
abstract class AesNumbers {

  /** Must be 16, 24 or 32 bytes long. */
  protected def secretKey: Array[Byte]
  
  private val keySpec = new SecretKeySpec(secretKey, "AES")

  private val random = new SecureRandom

  protected val base64: Base64Codec = Base64

  protected def encryptLong(clear: Long): String = {
    val salt = synchronized { random.nextInt() }
    encryptLong(clear, salt)
  }

  protected def encryptLong(clear: Long, salt: Int): String = {
    val cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
    cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keySpec)

    val parity = (clear >>> 32).toInt ^ clear.toInt ^ salt

    val in = new Array[Byte](16)
    in(0) = (clear >>> 56).toByte
    in(1) = (clear >>> 48).toByte
    in(2) = (clear >>> 40).toByte
    in(3) = (clear >>> 32).toByte
    in(4) = (clear >>> 24).toByte
    in(5) = (clear >>> 16).toByte
    in(6) = (clear >>> 8).toByte
    in(7) = clear.toByte
    in(8) = (salt >>> 24).toByte
    in(9) = (salt >>> 16).toByte
    in(10) = (salt >>> 8).toByte
    in(11) = salt.toByte
    in(12) = (parity >>> 24).toByte
    in(13) = (parity >>> 16).toByte
    in(14) = (parity >>> 8).toByte
    in(15) = parity.toByte

    val out = cipher.doFinal(in)
    Arrays.fill(in, 0.toByte)
    new String(base64.encode(out))
  }

  protected def decryptLong(cipherText: String): Option[Long] = {
    implicit val rts = strategy.throwExceptions
    if(cipherText.length == 22) {
      val in = base64.decode(cipherText)
      val cipher = javax.crypto.Cipher.getInstance("AES/ECB/NoPadding")
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec)
      val out = cipher.doFinal(in)

      val clear =
        (out(0) & 0xFFL) << 56 |
        (out(1) & 0xFFL) << 48 |
        (out(2) & 0xFFL) << 40 |
        (out(3) & 0xFFL) << 32 |
        (out(4) & 0xFFL) << 24 |
        (out(5) & 0xFFL) << 16 |
        (out(6) & 0xFFL) << 8 |
        (out(7) & 0xFFL)

      val salt =
        (out(8) & 0xFF) << 24 |
        (out(9) & 0xFF) << 16 |
        (out(10) & 0xFF) << 8 |
        (out(11) & 0xFF)

      val parity =
        (out(12) & 0xFF) << 24 |
        (out(13) & 0xFF) << 16 |
        (out(14) & 0xFF) << 8 |
        (out(15) & 0xFF)

      Arrays.fill(out, 0.toByte)
      if(parity == ((clear >>> 32).toInt ^ clear.toInt ^ salt)) Some(clear)
      else None
    } else None
  }
}

/** Encrypts a single Int value into a 22-character string. Adds 32 bits of
  * salt, 32 bits of parity and 32 bits of zeros (i.e. 64 bits of check data).
  * Compared to ObscuredNumbers, this class provides much better security at the
  * expense of a longer encrypted form. We expect that in the context of a web
  * application it will not be feasible for an attacker to perform enough
  * encryptions to break this scheme, however the generic AesEncryption
  * interface provides rather stronger theoretical guarantees.  This class is
  * threadsafe. */
abstract class AesInts extends AesNumbers {
  
  def encrypt(clear: Int): String = encryptLong(clear & 0xFFFFFFFFL)
  def encrypt(clear: Int, salt: Int): String = encryptLong(clear & 0xFFFFFFFFL, salt)
  def apply(clear: Int): String = encrypt(clear)
  def unapply(cipherText: String): Option[Int] = decrypt(cipherText)
  
  def decrypt(cipherText: String): Option[Int] =
    decryptLong(cipherText) match {
      case None => None
      case Some(longVal) =>
        if(longVal >>> 32 == 0) Some(longVal.toInt)
        else None
    }
}

/** Encrypts a single Long value into a 22-character string. Adds 32 bits of
  * salt and 32 bits of parity. Compared to ObscuredNumbers, this class provides
  * rather better security at the expense of a longer encrypted form. This is
  * somewhat weaker than AesInts, be we still expect that in the context of a
  * web application it will not generally be feasible for an attacker to perform
  * enough encryptions to break this scheme (or at least that it would be much
  * easier to crack the server some other way), however the generic
  * AesEncryption interface provides rather stronger theoretical guarantees.
  * This class is threadsafe. */
abstract class AesLongs extends AesNumbers {
  def encrypt(clear: Long): String = encryptLong(clear)
  def encrypt(clear: Long, salt: Int): String = encryptLong(clear, salt)
  def decrypt(cipherText: String): Option[Long] = decryptLong(cipherText)
  def apply(clear: Long): String = encrypt(clear)
  def unapply(cipherText: String): Option[Long] = decrypt(cipherText)
}
