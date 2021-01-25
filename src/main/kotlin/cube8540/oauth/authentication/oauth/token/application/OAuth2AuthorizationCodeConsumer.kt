package cube8540.oauth.authentication.oauth.token.application

import cube8540.oauth.authentication.oauth.token.domain.OAuth2AuthorizationCode
import java.util.*

interface OAuth2AuthorizationCodeConsumer {

    fun consume(code: String): Optional<OAuth2AuthorizationCode>
}