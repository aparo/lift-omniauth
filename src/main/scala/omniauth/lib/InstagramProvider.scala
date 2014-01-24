package omniauth.lib

import net.liftweb.util.Props
import scala.xml.NodeSeq
import omniauth.{AuthInfo, Omniauth}
import net.liftweb.http.S
import dispatch.:/
import net.liftweb.json.JsonParser
import net.liftweb.common.{Empty, Full, Box}
import net.liftweb.util.Helpers._

class InstagramProvider(val clientId:String, val secret:String) extends OmniauthProvider{
  def providerName = InstagramProvider.providerName
  def providerPropertyKey = InstagramProvider.providerPropertyKey
  def providerPropertySecret = InstagramProvider.providerPropertySecret

  def instagramPermissions =
    Props.get("omniauth.instagrampermissions") openOr "basic"

  def signIn():NodeSeq = doInstagramSignin
  def callback(): NodeSeq = doInstagramCallback
  implicit val formats = net.liftweb.json.DefaultFormats

  def doInstagramSignin() : NodeSeq = {
    val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"
    var urlParameters = Map[String, String]()
    urlParameters += ("client_id" -> clientId)
    urlParameters += ("redirect_uri" -> callbackUrl)
    urlParameters += ("scope" -> instagramPermissions)
    urlParameters += ("response_type" -> "code")
    urlParameters += ("scope" -> instagramPermissions)
    val requestUrl = :/("api.instagram.com").secure/"oauth"/"authorize" <<? urlParameters
    S.redirectTo(requestUrl.url)
  }

  def doInstagramCallback () : NodeSeq = {
    val ggCode = S.param("code") openOr S.redirectTo("/")
    val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"
    var urlParameters = Map[String, String]()
    urlParameters += ("client_id" -> clientId)
    urlParameters += ("redirect_uri" -> callbackUrl)
    urlParameters += ("client_secret" -> secret)
    urlParameters += ("grant_type" -> "authorization_code")
    urlParameters += ("code" -> ggCode.toString)

    val tempRequest = (:/("api.instagram.com").secure / "oauth" / "access_token").POST <:<
      Map("Content-Type" -> "application/x-www-form-urlencoded")<< urlParameters

    val json = Omniauth.json(tempRequest)
    val accessToken = tryo {
      AuthToken(
        (json \ "access_token").extract[String],
        None,
        None,
        None
      )
    }
    (for {
      t <- accessToken
      if validateToken(t)
    } yield { 
      
      val uid =  (json \ "user" \ "id").extract[String]
      val username =  (json \ "user" \ "username").extract[String]
      val full_name = (json \ "user" \ "full_name").extract[String].split(" ")
      
      val ai = AuthInfo(providerName, uid, username, t, Some(secret), Some(username), None, full_name.headOption, full_name.lastOption)
      Omniauth.setAuthInfo(ai)
      logger.debug(ai)
      S.redirectTo(Omniauth.successRedirect) 
      
    }) openOr S.redirectTo(Omniauth.failureRedirect)
  }

  def validateToken(accessToken:AuthToken): Boolean = {
    val tempRequest = :/("api.instagram.com").secure / "v1" / "users" / "self" / "feed" <<? Map("access_token" -> accessToken.token)

    try{
      Omniauth.json(tempRequest)
      true
    } catch {
      case _ : Throwable => false
    }
  }
  
  def tokenToId(accessToken:AuthToken): Box[String] = {
    None
  }

}

object InstagramProvider {
  val providerName = "instagram"
  val providerPropertyKey = "omniauth.instagramkey"
  val providerPropertySecret = "omniauth.instagramsecret"
}