package cube8540.oauth.authentication.security

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class AuthorityCode(var value: String): Serializable
