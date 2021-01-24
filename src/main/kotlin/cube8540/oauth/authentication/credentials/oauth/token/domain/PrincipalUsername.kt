package cube8540.oauth.authentication.credentials.oauth.token.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class PrincipalUsername(var value: String): Serializable