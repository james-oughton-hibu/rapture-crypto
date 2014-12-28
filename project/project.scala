object project extends ProjectSettings {
  def scalaVersion = "2.10.4"
  def version = "1.1.0"
  def name = "crypto"
  def description = "Rapture Crypto provides a variety of convenient cryptographic methods for use in Scala."
  
  def dependencies = Seq(
    "io" -> "1.1.0",
    "codec" -> "1.1.0"
  )
  
  def thirdPartyDependencies = Nil

  def imports = Seq(
    "rapture.core._",
    "rapture.crypto._"
  )
}
