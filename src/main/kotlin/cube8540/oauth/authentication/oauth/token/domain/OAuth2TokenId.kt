package cube8540.oauth.authentication.oauth.token.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class OAuth2TokenId(var value: String): Serializable
