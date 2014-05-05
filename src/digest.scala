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
import rapture.io._

import java.security._
import language.implicitConversions

trait DigestType
trait Sha1 extends DigestType
trait Sha256 extends DigestType
trait Sha384 extends DigestType
trait Sha512 extends DigestType
trait Md2 extends DigestType
trait Md5 extends DigestType

class Digest[T <: DigestType](bytes: Array[Byte]) extends ByteData(bytes)

object ByteData {
  implicit def stringByteData(string: String)(implicit enc: Encoding): ByteData =
    ByteData(string.getBytes(enc.name))
  
  implicit def arrayBytes(array: Array[Byte]): ByteData = ByteData(array)

  implicit def resourceBytes[Res](res: Res)(implicit sr: StreamReader[Res, Byte]) =
    ByteData(slurpable(res).slurp[Byte]())
}

case class ByteData(bytes: Array[Byte]) {
  def hex: String = Hex.encode(bytes)
  def base64: String = Base64.encode(bytes)
  override def toString = hex

  def zero() = (0 until bytes.length) foreach { bytes(_) = 0 }
}

class EncryptedData[C <: CipherType](bytes: Array[Byte]) extends ByteData(bytes)

object Hash {
  def digest[D <: DigestType: Digester](msg: ByteData): Digest[D] =
    new Digest[D](?[Digester[D]].digest(msg.bytes))
}

abstract class Digester[D <: DigestType] {
  /** Digests the array of bytes. */
  def digest(msg: Array[Byte]): Array[Byte]
}

object digests {

  implicit val sha1: Digester[Sha1] = new Digester[Sha1] {
    def digest(msg: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("SHA-1").digest(msg)
  }

  /** SHA-256 digester, with additional methods for secure password encoding. */
  implicit val sha256: Digester[Sha256] = new Digester[Sha256] {
    /** Digests the given bytes. */
    def digest(msg: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("SHA-256").digest(msg)
  }

  /** SHA-512 digester, with additional methods for secure password encoding. */
  implicit val sha512: Digester[Sha512] = new Digester[Sha512] {
    def digest(msg: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("SHA-512").digest(msg)
  }
  
  /** SHA-384 digester, with additional methods for secure password encoding. */
  implicit val sha384: Digester[Sha384] = new Digester[Sha384] {
    def digest(msg: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("SHA-384").digest(msg)
  }

  /** MD5 Digester. This is included for backwards compatibility. MD5 is no
    * longer considered future-proof and new designs should prefer SHA-256. */
  implicit val md5: Digester[Md5] = new Digester[Md5] {
    def digest(msg: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("MD5").digest(msg)
  }
  
  implicit val md2: Digester[Md2] = new Digester[Md2] {
    def digest(msg: Array[Byte]): Array[Byte] =
      MessageDigest.getInstance("MD2").digest(msg)
  }
}

trait CipherType
trait Blowfish extends CipherType
trait Aes extends CipherType
trait TripleDes extends CipherType
trait Des extends CipherType

trait KeyGenerator[K <: CipherType] {
  def generate(): Array[Byte]
}

object KeyGenerator {
  implicit val blowfishGenerator: KeyGenerator[Blowfish] = new KeyGenerator[Blowfish] {
    def generate(): Array[Byte] = {
      val keyGen = javax.crypto.KeyGenerator.getInstance("Blowfish")
      keyGen.generateKey().getEncoded
    }
  }
}

trait Encrypter[C <: CipherType] {
  def encrypt(key: Array[Byte], message: Array[Byte]): Array[Byte]
}

object Encrypter {
  implicit val blowfishEncrypter = new Encrypter[Blowfish] {
    def encrypt(key: Array[Byte], message: Array[Byte]) = {
      val cipher = javax.crypto.Cipher.getInstance("Blowfish")
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "Blowfish"))
      cipher.doFinal(message)
    }
  }
}

object Decrypter {
  implicit val blowfishDecrypter = new Decrypter[Blowfish] {
    def decrypt(key: Array[Byte], message: Array[Byte]) = {
      val cipher = javax.crypto.Cipher.getInstance("Blowfish")
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "Blowfish"))
      cipher.doFinal(message)
    }
  }
}

trait Decrypter[C <: CipherType] {
  def decrypt(key: Array[Byte], message: Array[Byte]): Array[Byte]
}

object Key {
  def generate[K <: CipherType: KeyGenerator](): Key[K] =
    new Key[K](?[KeyGenerator[K]].generate())

  def read[K <: CipherType](key: ByteData): Key[K] =
    new Key[K](key.bytes)
}

class Key[K <: CipherType](bytes: Array[Byte]) extends ByteData(bytes)

object Cipher {
  def encrypt[C <: CipherType: Encrypter](key: Key[C])(message: ByteData): EncryptedData[C] =
    new EncryptedData[C](?[Encrypter[C]].encrypt(key.bytes, message.bytes))

  def decrypt[C <: CipherType: Decrypter](key: Key[C])(message: EncryptedData[C]): ByteData =
    ByteData(?[Decrypter[C]].decrypt(key.bytes, message.bytes))
}



/*object HmacSha256 {

  import javax.crypto._

  def signer(key: Array[Byte]): Digester = new Digester[Hmac] {
    
    def digest(msg: Array[Byte]): Array[Byte] = {
      val mac = Mac.getInstance("HmacSHA256")
      val secretKey = new spec.SecretKeySpec(key, "HmacSHA256")
      mac.init(secretKey)
      mac.doFinal(msg)
    }
  }
}*/
