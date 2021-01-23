package cube8540.oauth.authentication.credentials.oauth.token.domain

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.time.LocalDateTime

@ApiModel(value = "엑세스 토큰 클라이언트 정보")
interface AccessTokenClient {

    @get:ApiModelProperty(value = "클라이언트 아이디")
    val clientId: String?

    @get:ApiModelProperty(value = "클라이언트명")
    val clientName: String?
}

@ApiModel(value = "엑세스 토큰 및 클라이언트 정보")
interface AccessTokenDetailsWithClient {

    @get:ApiModelProperty(value = "OAuth2 엑세스 토큰", required = true, example = "xxxxxxxxxxx")
    val tokenValue: String?

    val client: AccessTokenClient?

    @get:ApiModelProperty(value = "OAuth2 엑세스 토큰 소유자", required = true, example = "username1234")
    val username: String?

    @get:ApiModelProperty(value = "OAuth2 엑세스 토큰 발행 시간", required = true, example = "2020-05-18T05:13:00")
    val issuedAt: LocalDateTime?

    @get:ApiModelProperty(value = "OAuth2 엑세스 토큰 만료 까지 남은 시간", required = true, example = "599")
    val expiresIn: Long?

    @get:ApiModelProperty(value = "OAuth2 엑세스 토큰 추가 정보")
    val additionalInformation: Map<String, String?>?
}