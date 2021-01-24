package cube8540.oauth.authentication.credentials.oauth.client.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class ClientOwner(var value: String): Serializable