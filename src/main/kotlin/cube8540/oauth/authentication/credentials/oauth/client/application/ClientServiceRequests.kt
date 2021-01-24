package cube8540.oauth.authentication.credentials.oauth.client.application

import io.swagger.annotations.ApiModel
import io.swagger.annotations.ApiModelProperty
import java.beans.ConstructorProperties

@ApiModel(value = "OAuth2 클라이언트 등록 정보")
data class OAuth2ClientRegisterRequest @ConstructorProperties(value = [
    "clientId", "secret", "clientName", "redirectUris", "scopes", "grantTypes", "accessTokenValiditySeconds", "refreshTokenValiditySeconds", "clientOwner"
]) constructor(

    @ApiModelProperty(value = "등록할 클라이언트 아이디", required = true, example = "client-id")
    val clientId: String,

    @ApiModelProperty(value = "등록할 클라이언트 패스워드", required = true, example = "client-secret")
    val secret: String,

    @ApiModelProperty(value = "등록할 클라이언트명", required = true, example = "client name")
    val clientName: String?,

    @ApiModelProperty(value = "Authorization Code 인증에서 사용할 리다이렉트 URI", required = true, example = "[\"http://localhost:8080/callback\", \"http://localhost:8081/callback\"]")
    val redirectUris: List<String>?,

    @ApiModelProperty(value = "이 클라이언트로 부여 받을 수 있는 스코프", required = true, example = "[\"TEST-1\", \"TEST-2\", \"TEST-3\"]")
    val scopes: List<String>?,

    @ApiModelProperty(value = "클라이언트가 제공하는 인증 방식", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    val grantTypes: List<String>?,

    @ApiModelProperty(value = "엑세스 토큰 유효 기간 (초)", example = "60")
    val accessTokenValiditySeconds: Int?,

    @ApiModelProperty(value = "리플레시 토큰 유효 기간 (초)", example = "600")
    val refreshTokenValiditySeconds: Int?,

    @ApiModelProperty(value = "클라이언트 소유자", required = true, example = "username1234")
    val clientOwner: String?
)

data class OAuth2ClientModifyRequest @ConstructorProperties(value = [
    "clientName", "newRedirectUris", "removeRedirectUri", "newGrantTypes", "removeGrantTypes", "newScopes", "removeScopes", "accessTokenValiditySeconds", "refreshTokenValiditySeconds"
]) constructor(

    @ApiModelProperty(value = "변경할 클라이언트명", required = true, example = "client-name")
    val clientName: String?,

    @ApiModelProperty(value = "추가할 리다이렉트 URI 빈 배열 일시 리다이렉트 URI을 추가 하지 않습니다.", required = true, example = "[\"http://localhost:8082/callback\", \"http://localhost:8083/callback\"]")
    val newRedirectUris: List<String>?,

    @ApiModelProperty(value = "삭제할 리다이렉트 URI 빈 배열 일시 리다이렉트 URI을 삭제 하지 않습니다.", required = true, example = "[\"http://localhost:8080/callback\", \"http://localhost:8081/callback\"]")
    val removeRedirectUris: List<String>?,

    @ApiModelProperty(value = "추가할 인증 타입 빈 배열 일시 인증 타입을 추가 하지 않습니다.", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    val newGrantTypes: List<String>?,

    @ApiModelProperty(value = "삭제할 인증 타입 빈 배열 일시 인증 타입을 삭제 하지 않습니다.", required = true, example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
    val removeGrantTypes: List<String>?,

    @ApiModelProperty(value = "추가할 스코프 빈 배열 일시 스코프를 추가 하지 않습니다.", required = true, example = "[\"TEST-1\", \"TEST-2\"]")
    val newScopes: List<String>?,

    @ApiModelProperty(value = "삭제할 스코프 빈 배열 일시 스코프를 삭제 하지 않습니다.", required = true, example = "[\"TEST-1\", \"TEST-2\"]")
    val removeScopes: List<String>?,

    @ApiModelProperty(value = "엑세스 토큰 유효 기간 (초)", example = "60")
    val accessTokenValiditySeconds: Int?,

    @ApiModelProperty(value = "리플레시 토큰 유효 기간 (초)", example = "600")
    val refreshTokenValiditySeconds: Int?
)

@ApiModel(value = "OAuth2 클라이언트 패스워드 수정 정보")
data class OAuth2ChangeSecretRequest @ConstructorProperties(value = ["existsSecret", "newSecret"]) constructor(

    @ApiModelProperty(value = "변경할 클라이언트의 기존에 사용하던 패스워드", required = true, example = "client-secret")
    val existsSecret: String,

    @ApiModelProperty(value = "변경할 클라이언트 패스워드", required = true, example = "new-client-secret")
    val newSecret: String
)