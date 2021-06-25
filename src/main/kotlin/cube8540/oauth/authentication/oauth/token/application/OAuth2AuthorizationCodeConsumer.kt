package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode

interface OAuth2AuthorizationCodeConsumer {

    fun consume(code: String): OAuth2AuthorizationCode?
}