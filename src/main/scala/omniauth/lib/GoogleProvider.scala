package omniauth.lib

import net.liftweb.util.Props
import scala.xml.NodeSeq
import omniauth.{AuthInfo, Omniauth}
import net.liftweb.http.S
import dispatch.:/
import net.liftweb.json.JsonParser
import net.liftweb.common.{Empty, Full, Box}
import net.liftweb.util.Helpers._

/**
 * User: ggarcia
 * Date: 11/6/13
 * Time: 8:11 PM
 */
class GoogleProvider(val clientId:String, val secret:String) extends OmniauthProvider{
  def providerName = GoogleProvider.providerName
  def providerPropertyKey = GoogleProvider.providerPropertyKey
  def providerPropertySecret = GoogleProvider.providerPropertySecret

  def googlePermissions = Props.get("omniauth.googlepermissions") openOr ""
  def googleAccessType = Props.get("omniauth.googleaccesstype") openOr "online"

  def signIn():NodeSeq = doGoogleSignin
  def callback(): NodeSeq = doGoogleCallback
  implicit val formats = net.liftweb.json.DefaultFormats

  def doGoogleSignin() : NodeSeq = {
    val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"
    val requestUrl = :/("accounts.google.com").secure /"o"/"oauth2"/"auth" <<? Map(
      "client_id" -> clientId,
      "redirect_uri" -> callbackUrl,
      "access_type" -> googleAccessType,
      "scope" -> googlePermissions,
      "response_type" -> "code",
    "scope" -> googlePermissions)
    S.redirectTo(requestUrl.url)
  }

  def doGoogleCallback () : NodeSeq = {
    execWithStateValidation {
      val ggCode = S.param("code") openOr S.redirectTo("/")
      val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"
      var urlParameters = Map[String, String]()
      urlParameters += ("client_id" -> clientId)
      urlParameters += ("redirect_uri" -> callbackUrl)
      urlParameters += ("client_secret" -> secret)
      urlParameters += ("grant_type" -> "authorization_code")
      urlParameters += ("code" -> ggCode.toString)

      val tempRequest = (:/("accounts.google.com").secure / "o" / "oauth2" / "token").POST <:<
        Map("Content-Type" -> "application/x-www-form-urlencoded")<< urlParameters

      val json = Omniauth.json(tempRequest)
      val accessToken = tryo {
        AuthToken(
          (json \ "access_token").extract[String],
          (json \ "expires_in").extract[Option[Long]],
          (json \ "refresh_token").extract[Option[String]],
          None
        )
      }

      (for {
        t <- accessToken
        if validateToken(t)
      } yield { S.redirectTo(Omniauth.successRedirect) }) openOr S.redirectTo(Omniauth.failureRedirect)
    }
  }

  def validateToken(accessToken: AuthToken): Boolean = {
    val tempRequest = :/("www.googleapis.com").secure / "oauth2" / "v1" / "userinfo" <<?
      Map("access_token" -> accessToken.token)

    try{
      val json = Omniauth.json(tempRequest)

      val uid =  (json \ "id").extract[String]
      val name =  (json \ "name").extract[String]
      val firstName = (json \ "given_name").extract[String]
      val lastName = (json \ "family_name").extract[String]
      val email = (json \ "email").extract[String]
      val ai = AuthInfo(providerName,uid,name,accessToken,Some(secret),
        Some(name), Some(email), Some(firstName), Some(lastName))
      Omniauth.setAuthInfo(ai)
      logger.debug(ai)

      true
    } catch {
      case _ : Throwable => false
    }
  }

  def tokenToId(accessToken: AuthToken): Box[String] = {
    val tempRequest = :/("googleapis.com").secure / "v1" / "userinfo" <<?
      Map("access_token" -> accessToken.token)

    try{
      val json = Omniauth.json(tempRequest)
      Full((json \ "id").extract[String])
    } catch {
      case _ : Throwable => Empty
    }
  }

}

object GoogleProvider {
  val providerName = "google"
  val providerPropertyKey = "omniauth.googlekey"
  val providerPropertySecret = "omniauth.googlesecret"
}


