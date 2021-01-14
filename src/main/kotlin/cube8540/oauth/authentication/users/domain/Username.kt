package cube8540.oauth.authentication.users.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class Username(var value: String): Serializable