package cube8540.oauth.authentication.users.endpoint

import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import cube8540.oauth.authentication.users.application.UserCredentialsService
import io.swagger.annotations.Api
import io.swagger.annotations.ApiImplicitParam
import io.swagger.annotations.ApiOperation
import io.swagger.annotations.ApiParam
import io.swagger.annotations.ApiResponse
import io.swagger.annotations.ApiResponses
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping(value = ["/api/accounts"])
@Api(value = "유저 계정 인증 API 엔드 포인트")
class UserCredentialsAPIEndpoint @Autowired constructor(
    private val service: UserCredentialsService
) {

    @set:[Autowired Qualifier("userExceptionTranslator")]
    lateinit var translator: ExceptionTranslator<ErrorMessage<Any>>

    @PatchMapping(value = ["/attributes/active"])
    @ApiOperation(value = "계정 활성화", notes = "처음 계정을 등록할 시 할당 받은 계정 활성화 키를 이용하여 계정을 활성화 시킵니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 403, message = "OAuth2 토큰이 잘못 되었거나, 키가 일치 하지 않거나, 만료 되었습니다."),
        ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun credentials(
        @ApiParam(value = "활성화 시킬 유저 아이디", required = true, example = "username1234") @RequestParam username: String,
        @ApiParam(value = "계정 활성화 키", required = true, example = "xxxxxxxx") @RequestParam credentialsKey: String
    ) = service.accountCredentials(username, credentialsKey)

    @PostMapping(value = ["/{username}/attributes/credentials-key"])
    @ApiOperation(value = "계정 인증키 할당", notes = "계정의 활성화에 필요한 인증키를 할당 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 403, message = "OAuth2 토큰이 잘못 되었거나, 이미 인증된 계정 입니다."),
        ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun generateCredentialsKey(
        @ApiParam(value = "인증키를 할당할 유저 아이디", required = true, example = "username1234") @PathVariable username: String
    ) = service.grantCredentialsKey(username)

    @ExceptionHandler(Exception::class)
    fun handle(e: Exception): ResponseEntity<ErrorMessage<Any>> = translator.translate(e)

}