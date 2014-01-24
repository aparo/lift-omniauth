/*
 * Copyright 2010-2013 Matthew Henderson
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package omniauth.lib
import omniauth.Omniauth
import dispatch._
import xml.NodeSeq
import net.liftweb.http._
import net.liftweb.common._
import omniauth.AuthInfo
import net.liftweb.util.Helpers._
import org.scribe.builder.ServiceBuilder
import org.scribe.builder.api.TwitterApi
import org.scribe.model._
import net.liftweb.json._
import org.scribe.model.Token

case class TwitterPerson(name: String, id: Int, screen_name:String){

}
case class TwitterFriends(users: List[TwitterPerson])

object accessTokenSess extends SessionVar[Box[Token]](Empty)
object twitterSession extends SessionVar[Box[TwitterPerson]](Empty)

class TwitterProvider(val key:String, val secret:String) extends OmniauthProvider {
  def providerName = TwitterProvider.providerName
  def providerPropertyKey = TwitterProvider.providerPropertyKey
  def providerPropertySecret = TwitterProvider.providerPropertySecret

  def signIn(): NodeSeq = doTwitterSignin
  def callback(): NodeSeq = doTwitterCallback
  implicit val formats = net.liftweb.json.DefaultFormats
  lazy val callbackUrl = Omniauth.siteAuthBaseUrl+"auth/"+providerName+"/callback"

  val consumer = new ServiceBuilder().provider(classOf[TwitterApi])
    .apiKey(key)
    .apiSecret(secret)
    .callback(callbackUrl)
    .build()


  //def twitterAuthenticateUrl(token: Token) = Omniauth.twitterOauthRequest / "authenticate" with_token token

  def doTwitterSignin () : NodeSeq = {
    logger.debug("doTwitterSignin")
    logger.debug(consumer)
    logger.debug(callbackUrl)
    val requestToken = consumer.getRequestToken
    val auth_uri = consumer.getAuthorizationUrl(requestToken)
    logger.debug(auth_uri.toString)
    Omniauth.setRequestToken(requestToken)
    S.redirectTo(auth_uri.toString)
  }

  def doTwitterCallback () : NodeSeq = {
    logger.debug("doTwitterCallback")
    for {
      oAuthVerifier <- S.param("oauth_verifier")
      requestToken <- Omniauth.currentRequestToken
    } yield {
      val verifier = new Verifier(oAuthVerifier)
      val accessToken = consumer.getAccessToken(requestToken, verifier)

      val person = fetchTwitterPerson(requestToken, accessToken)

      twitterSession(Full(person))

      accessTokenSess(Full(accessToken))
      val authToken = AuthToken(accessToken.getToken, None, None, emptyForBlank(accessToken.getSecret))
      val ai = AuthInfo(providerName,person.id.toString,person.name,authToken,Some(accessToken.getSecret),Some(person.screen_name))
      Omniauth.setAuthInfo(ai)
      logger.debug(ai)
      return S.redirectTo(Omniauth.successRedirect)
    }
   S.redirectTo(Omniauth.failureRedirect)
  }

  def tokenToId(accessToken:AuthToken): Box[String] = {
    val tokenParts = accessToken.token.split(",")
    if(tokenParts.length != 2){
      logger.debug("tokenParts.length != 2: "+accessToken)
      return Empty
    }
//    val authToken = Token(tokenParts(0), tokenParts(1))
//    logger.debug("authToken "+authToken)
//    val verifyCreds = Omniauth.TwitterHost / "1.1/account/verify_credentials.json" <@ (consumer, authToken)
    try{
      val requestToken = Omniauth.currentRequestToken
      val person = fetchTwitterPerson(requestToken.get, new Token(accessToken.token,accessToken.secret.get))
      Full(person.id.toString)
    }catch {
      case e:Exception =>
        logger.debug("Exception= "+e)
        Empty
    }
  }

  def fetchTwitterPerson(requestToken: Token, accessToken: Token):TwitterPerson = {
    val request = new OAuthRequest(
      Verb.GET,
      "http://api.twitter.com/1.1/account/verify_credentials.json?skip_status=true"
    )

    consumer.signRequest(accessToken, request)

    parse(request.send().getBody).extract[TwitterPerson]
  }

  def fetchUserFriends = {
    val request = new OAuthRequest(
      Verb.GET,
      "http://api.twitter.com/1.1/friends/list.json?skip_status=true"
    )

    val friends = for {
      token <- accessTokenSess
    } yield {
      consumer.signRequest(token, request)

      parse(request.send().getBody).extract[TwitterFriends].users
    }

    friends.openOr(Nil)
  }

  def validateToken(token: AuthToken): Boolean = {
    try{
      val requestToken = Omniauth.currentRequestToken
      fetchTwitterPerson(requestToken.get, new Token(token.token,token.secret.get))
      true
    }catch {
      case e:Exception =>
        logger.debug("Exception= "+e)
        false
    }

  }
}

object TwitterProvider{
  val providerName:String = "twitter"
  val providerPropertyKey = "omniauth.twitterkey"
  val providerPropertySecret = "omniauth.twittersecret"
}
