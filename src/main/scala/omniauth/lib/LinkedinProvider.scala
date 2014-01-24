package omniauth.lib

import net.liftweb.util.Props
import scala.xml.{XML, NodeSeq}
import omniauth.{AuthInfo, Omniauth}
import net.liftweb.http.S
import dispatch.:/
import net.liftweb.util.Helpers._
import scala.Some
import net.liftweb.json.JsonParser
import net.liftweb.common.{Empty, Full, Box}

/**
 * User: ggarcia
 * Date: 11/7/13
 * Time: 8:43 AM
 */
class LinkedinProvider(val clientId:String, val secret:String) extends OmniauthProvider{
  def providerName = LinkedinProvider.providerName
  def providerPropertyKey = LinkedinProvider.providerPropertyKey
  def providerPropertySecret = LinkedinProvider.providerPropertySecret

  def linkedinPermissions =
    Props.get("omniauth.linkedinpermissions") openOr "r_emailaddress,r_basicprofile"

  def signIn():NodeSeq = doLinkedinSignin
  def callback(): NodeSeq = doLinkedinCallback
  implicit val formats = net.liftweb.json.DefaultFormats

  def doLinkedinSignin() : NodeSeq = {
    val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"
    var urlParameters = Map[String, String]()
    urlParameters += ("client_id" -> clientId)
    urlParameters += ("redirect_uri" -> callbackUrl)
    urlParameters += ("scope" -> linkedinPermissions)
    urlParameters += ("response_type" -> "code")
    urlParameters += ("scope" -> linkedinPermissions)
    urlParameters += ("state" -> csrf)
    var requestUrl = :/("www.linkedin.com").secure/"uas"/"oauth2"/"authorization"<<? urlParameters
    S.redirectTo(requestUrl.url)
  }

  def doLinkedinCallback () : NodeSeq = {
    execWithStateValidation {
      val ggCode = S.param("code") openOr S.redirectTo("/")
      val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"
      var urlParameters = Map[String, String]()
      urlParameters += ("client_id" -> clientId)
      urlParameters += ("redirect_uri" -> callbackUrl)
      urlParameters += ("client_secret" -> secret)
      urlParameters += ("grant_type" -> "authorization_code")
      urlParameters += ("code" -> ggCode.toString)

      val tempRequest = (:/("www.linkedin.com").secure / "uas" / "oauth2" / "accessToken").POST << urlParameters

      val json = Omniauth.json(tempRequest)
      val accessToken = tryo {
        AuthToken(
          (json \ "access_token").extract[String],
          (json \ "expires_in").extract[Option[Long]],
          None,
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
    val urlParameters = Map("oauth2_access_token" -> accessToken.token,
      "format" -> "json")
    val profile = "~:(id,first-name,last-name,email-address)"
    val tempRequest = :/("api.linkedin.com").secure / "v1" / "people" / profile <<? urlParameters

    val json = Omniauth.json(tempRequest)

    val uid = (json \ "id").extract[String]
    val firstName = (json \ "firstName").extract[String]
    val lastName = (json \ "lastName").extract[String]
    val name = firstName + " " + lastName
    val email = (json \ "emailAddress").extract[String]
    val ai = AuthInfo(providerName, uid, name, accessToken, Some(secret),
      Some(name), Some(email), Some(firstName), Some(lastName))
    Omniauth.setAuthInfo(ai)
    logger.debug(ai)

    true
  }

  def tokenToId(accessToken:AuthToken): Box[String] = {

    val tempRequest = :/("api.linkedin.com").secure / "v1" / "people" / "~" / "id" <<?
      Map("access_token" -> accessToken.token)

    try{
      val xml = Omniauth.xml(tempRequest)
      Full((xml \ "id")text)
    } catch {
      case _ : Throwable => Empty
    }
  }

}

object LinkedinProvider {
  val providerName = "linkedin"
  val providerPropertyKey = "omniauth.linkedinkey"
  val providerPropertySecret = "omniauth.linkedinsecret"
}


