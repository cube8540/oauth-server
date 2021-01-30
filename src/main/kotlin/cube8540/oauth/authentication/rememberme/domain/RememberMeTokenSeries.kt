package cube8540.oauth.authentication.rememberme.domain

import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class RememberMeTokenSeries(var value: String): Serializable