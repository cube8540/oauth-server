package cube8540.oauth.authentication.security

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.io.Serializable
import javax.persistence.Embeddable

@Embeddable
data class AuthorityCode(var value: String): Serializable

@ApiModel(value = "권한 상세 정보")
interface AuthorityDetails {

    @get:ApiModelProperty(value = "권한 코드", required = true, example = "AUTH_USER")
    val code: String

    @get:ApiModelProperty(value = "권한 설명", required = true, example = "Default User Authority")
    val description: String
}

interface AuthorityDetailsService {

    fun loadAuthorityByAuthorityCodes(authorities: Collection<String>): Collection<AuthorityDetails>

    fun loadInitializeAuthority(): Collection<AuthorityDetails>
}