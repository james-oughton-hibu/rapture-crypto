/**********************************************************************************************\
* Rapture Crypto Library                                                                       *
* Version 0.9.0                                                                                *
*                                                                                              *
* The primary distribution site is                                                             *
*                                                                                              *
*   http://rapture.io/                                                                         *
*                                                                                              *
* Copyright 2010-2013 Propensive Ltd.                                                          *
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
package rapture

import rapture.core._

package object crypto {
 
  // FIXME: Integrate
  /*implicit class DigestExtras[UrlType](url: UrlType) {
    def md5Sum()(implicit sr: StreamReader[UrlType, Byte], eh: ExceptionHandler):
      eh.![Exception, String] = eh.except {
        Md5.digestHex(slurp[Byte]())
      }
    
    def sha256Sum()(implicit sr: StreamReader[UrlType, Byte], eh: ExceptionHandler):
      eh.![Exception, String] = eh.except {
        Sha256.digestHex(slurp[Byte]())
      }
  }*/

}
