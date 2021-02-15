package cube8540.oauth.authentication.users.endpoint

import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import cube8540.oauth.authentication.users.application.UserManagementService
import cube8540.oauth.authentication.users.application.UserRegisterRequest
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
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
@RequestMapping(value = ["/api/accounts"])
@Api(value = "유저 계정 관리 API 엔드 포인트")
class UserManagementAPIEndpoint @Autowired constructor(
    private val service: UserManagementService
) {

    @set:[Autowired Qualifier("userExceptionTranslator")]
    lateinit var translator: ExceptionTranslator<ErrorMessage<Any>>

    @GetMapping(value = ["/{username}"])
    @ApiOperation(value = "계정 정보 검색", notes = "요청 받은 계정의 정보를 반환 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun getProfile(@ApiParam(name = "username", required = true, example = "username1234") @PathVariable username: String) =
        service.loadUserProfile(username)

    @DeleteMapping(value = ["/{username}"])
    @ApiOperation(value = "계정 삭제", notes = "요청한 계정을 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun removeProfile(@ApiParam(name = "username", required = true, example = "username1234") @PathVariable username: String) =
        service.removeUser(username)

    @PostMapping
    @ApiOperation(value = "계정 등록", notes = "새 계정을 등록 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "요청하신 아이디가 중복 되었거나, 매개 변수의 형식이 옳바르지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun registerUserAccounts(@RequestBody registerRequest: UserRegisterRequest) = service.registerUser(registerRequest)

    @GetMapping(value = ["/attributes/username"])
    @ApiOperation(value = "등록된 아이디 갯수 검색", notes = "매개 변수로 받은 아이디의 갯수를 검색 합니다. 주로 아이디 중복 검사에서 사용 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")]
    )
    fun countAccountUsername(@ApiParam(value = "검색할 아이디", required = true, example = "username1234") @RequestParam username: String): Map<String, Long> {
        val count = service.countUser(username)
        return Collections.singletonMap("count", count)
    }

    @ExceptionHandler(Exception::class)
    fun handle(e: Exception): ResponseEntity<ErrorMessage<Any>> = translator.translate(e)
}