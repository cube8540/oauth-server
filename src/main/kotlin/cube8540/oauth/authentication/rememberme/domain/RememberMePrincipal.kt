package cube8540.oauth.authentication.rememberme.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class RememberMePrincipal(var value: String): Serializable