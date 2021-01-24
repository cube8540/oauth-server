package cube8540.oauth.authentication.oauth.scope.endpoint

import cube8540.oauth.authentication.security.AuthorityDetails
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeManagementService
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeModifyRequest
import cube8540.oauth.authentication.oauth.scope.application.OAuth2ScopeRegisterRequest
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
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
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
class ScopeManagementAPIEndpoint @Autowired constructor(
    private val managementService: OAuth2ScopeManagementService
) {
    @set:[Autowired Qualifier("scopeAPIExceptionTranslator")]
    lateinit var translator: ExceptionTranslator<ErrorMessage<Any>>

    @GetMapping(value = ["/api/scopes"])
    @ApiOperation(value = "스코프 검색", notes = "스코프를 반환 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun scope(): Map<String, Collection<AuthorityDetails>> {
        val scopes = managementService.loadScopes()
        return Collections.singletonMap("scopes", scopes)
    }

    @PostMapping(value = ["/api/scopes"])
    @ApiOperation(value = "새 스코프 등록", notes = "새 스코프를 등록 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "이미 사용중인 스코프 아이디 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun registerNewScope(@RequestBody registerRequest: OAuth2ScopeRegisterRequest) =
        managementService.registerNewScope(registerRequest)

    @PutMapping(value = ["/api/scopes/{id}"])
    @ApiOperation(value = "스코프 수정", notes = "스코프의 정보를 변경 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "요청 정보중 허용 되지 않는 정보가 있습니다."),
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "요청 하신 스코프는 등록 되지 않은 스코프 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun modifyScope(@PathVariable id: String, @RequestBody modifyRequest: OAuth2ScopeModifyRequest) =
        managementService.modifyScope(id, modifyRequest)

    @DeleteMapping(value = ["/api/scopes/{id}"])
    @ApiOperation(value = "스코프 삭제", notes = "스코프를 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "요청 하신 스코프는 등록 되지 않은 스코프 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun removeScope(@PathVariable id: String) = managementService.removeScope(id)

    @GetMapping(value = ["/api/scopes/attributes/scopeId"])
    @ApiOperation(value = "스코프 아이디 갯수 검색", notes = "매개 변수로 받은 스코프의 갯수를 검색 합니다. 주로 스코프 중복 검사에서 사용 합니다.")
    fun countScopeId(@ApiParam(value = "스코프 아이디", required = true, example = "scope") @RequestParam id: String): Map<String, Long> {
        val count = managementService.countByScopeId(id)

        return Collections.singletonMap("count", count)
    }

    @ExceptionHandler(value = [Exception::class])
    fun handle(e: Exception): ResponseEntity<ErrorMessage<Any>> = translator.translate(e)
}