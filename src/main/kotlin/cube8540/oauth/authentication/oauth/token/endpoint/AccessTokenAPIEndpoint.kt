package cube8540.oauth.authentication.oauth.token.endpoint

import cube8540.oauth.authentication.oauth.security.OAuth2TokenDetails
import cube8540.oauth.authentication.oauth.security.OAuth2TokenRevoker
import cube8540.oauth.authentication.oauth.token.application.AccessTokenReadService
import cube8540.oauth.authentication.oauth.token.domain.AccessTokenDetailsWithClient
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import io.swagger.annotations.Api
import io.swagger.annotations.ApiImplicitParam
import io.swagger.annotations.ApiOperation
import io.swagger.annotations.ApiParam
import io.swagger.annotations.ApiResponse
import io.swagger.annotations.ApiResponses
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.lang.Exception
import java.util.*

@RestController
@Api(value = "OAuth2 엑세스 토큰 API 엔드 포인트")
class AccessTokenAPIEndpoint @Autowired constructor(
    private val service: AccessTokenReadService,

    @Qualifier("defaultTokenRevoker")
    private val revoker: OAuth2TokenRevoker
) {

    @set:[Autowired Qualifier("tokenExceptionTranslator")]
    lateinit var translator: ExceptionTranslator<ErrorMessage<Any>>

    @GetMapping(value = ["/api/tokens"])
    @ApiOperation(value = "OAuth2 토큰 검색", notes = "요청 받은 유저의 엑세스 토큰을 검색 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다.")
    ])
    fun getUserAccessToken(@ApiParam(name = "username", required = true, example = "username1234") @RequestParam username: String):
            Map<String, List<AccessTokenDetailsWithClient>> {
        val tokens = service.getAuthorizeAccessTokens(username)
        return Collections.singletonMap("tokens", tokens)
    }

    @DeleteMapping(value = ["/api/tokens/{accessToken}"])
    @ApiOperation(value = "OAuth2 토큰  삭제", notes = "OAuth 토큰을 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "요청 하신 토큰은 등록 되지 않은 토큰 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun deleteUserAccessToken(@ApiParam(value = "삭제할 엑세스 토큰", required = true, example = "xxxxxxxxxx") @PathVariable accessToken: String):
            OAuth2TokenDetails = revoker.revoke(accessToken)

    @ExceptionHandler(Exception::class)
    fun exceptionHandling(e: Exception): ResponseEntity<ErrorMessage<Any>> = translator.translate(e)

}