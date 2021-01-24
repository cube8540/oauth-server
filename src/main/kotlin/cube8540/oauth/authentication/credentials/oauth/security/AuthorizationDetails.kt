package cube8540.oauth.authentication.credentials.oauth.security

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import org.springframework.security.oauth2.core.AuthorizationGrantType
import java.net.URI
import java.time.LocalDateTime

@ApiModel(value = "OAuth2 토큰 상세 정보")
interface OAuth2TokenDetails {

    @get:ApiModelProperty(value = "OAuth2 토큰", required = true, example = "xxxxxxxxxx")
    val tokenValue: String

    @get:ApiModelProperty(value = "OAuth2 토큰 만료 시간", required = true, example = "2020-05-18T05:13:00")
    val expiration: LocalDateTime

    @get:ApiModelProperty(value = "OAuth2 토큰 만료 여부", required = true, example = "false")
    val expired: Boolean

    @get:ApiModelProperty(value = "OAuth2 토큰 만료 까지 남은 시간", required = true, example = "599")
    val expiresIn: Long
}

@ApiModel(value = "OAuth2 클라이언트 상세 정보")
interface OAuth2ClientDetails {
    @get:ApiModelProperty(value = "클라이언트 아이디", required = true, example = "client-id")
    val clientId: String

    @get:ApiModelProperty(value = "클라이언트 패스워드", required = true, example = "client-secret")
    val clientSecret: String?

    @get:ApiModelProperty(value = "클라이언트명", required = true, example = "client name")
    val clientName: String?

    @get:ApiModelProperty(value = "클라이언트 라디이렉트 URI", required = true, example = "[\"http://localhost:8082/callback\", \"http://localhost:8083/callback\"]")
    val registeredRedirectUris: Set<URI>?

    @get:ApiModelProperty(value = "클라이언트 인증 타입", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    val authorizedGrantTypes: Set<AuthorizationGrantType>?

    @get:ApiModelProperty(value = "클라이언트 스코프", required = true, example = "[\"TEST-1\", \"TEST-2\"]")
    val scopes: Set<String>

    @get:ApiModelProperty(value = "클라이언트 소유자", required = true, example = "username1234")
    val owner: String?

    @get:ApiModelProperty(value = "클라이언트 엑세스 토큰 유효 시간", required = true, example = "600000000000")
    val accessTokenValiditySeconds: Int?

    @get:ApiModelProperty(value = "클라이언트 리플래시 토큰 유효 시간", required = true, example = "7200000000000")
    val refreshTokenValiditySeconds: Int?
}

interface OAuth2RefreshTokenDetails: OAuth2TokenDetails

interface OAuth2AccessTokenDetails: OAuth2TokenDetails {
    val clientId: String?

    val scopes: Set<String>?

    val tokenType: String?

    val username: String?

    val refreshToken: OAuth2RefreshTokenDetails?

    val additionalInformation: Map<String, String?>?
}