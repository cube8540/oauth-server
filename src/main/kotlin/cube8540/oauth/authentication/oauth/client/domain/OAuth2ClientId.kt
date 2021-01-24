package cube8540.oauth.authentication.oauth.client.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class OAuth2ClientId(var value: String): Serializable