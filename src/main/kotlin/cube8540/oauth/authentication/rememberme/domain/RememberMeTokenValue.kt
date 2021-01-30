package cube8540.oauth.authentication.rememberme.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class RememberMeTokenValue(var value: String): Serializable