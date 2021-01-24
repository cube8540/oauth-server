package cube8540.oauth.authentication.resource.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class SecuredResourceId(var value: String): Serializable