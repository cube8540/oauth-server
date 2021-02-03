package cube8540.oauth.authentication.users.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class Uid(var value: String): Serializable