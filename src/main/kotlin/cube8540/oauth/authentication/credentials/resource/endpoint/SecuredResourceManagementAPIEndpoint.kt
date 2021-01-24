package cube8540.oauth.authentication.credentials.resource.endpoint

import cube8540.oauth.authentication.credentials.resource.application.SecuredResourceDetails
import cube8540.oauth.authentication.credentials.resource.application.SecuredResourceManagementService
import cube8540.oauth.authentication.credentials.resource.application.SecuredResourceModifyRequest
import cube8540.oauth.authentication.credentials.resource.application.SecuredResourceRegisterRequest
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
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.*

@RestController
@Api(value = "보호 자원 관리 API 엔드 포인트")
class SecuredResourceManagementAPIEndpoint @Autowired constructor(private val service: SecuredResourceManagementService) {

    @set:[Autowired Qualifier("securedResourceExceptionTranslator")]
    lateinit var translator: ExceptionTranslator<ErrorMessage<Any>>

    @GetMapping(value = ["/api/secured-resources/attributes/resource-id"])
    @ApiOperation(value = "자원 아이디 갯수 검색", notes = "저장소에 저장된 자원 아이디의 갯수를 검색 합니다. 주로 자원 아이디 중복 검사에서 사용 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    fun countResourceId(@ApiParam(value = "자원 아이디", required = true, example = "resource-id") @RequestParam resourceId: String): Map<String, Long> {
        val count = service.count(resourceId)
        return Collections.singletonMap("count", count)
    }

    @GetMapping(value = ["/api/secured-resources"])
    @ApiOperation(value = "등록된 보호 자원 검색", notes = "저장소에 저장된 모든 보호 자원을 검색 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun getResources(): Map<String, List<SecuredResourceDetails>> {
        val resources = service.getResources()
        return Collections.singletonMap("resources", resources)
    }

    @PostMapping(value = ["/api/secured-resources"])
    @ApiOperation(value = "보호 자원 등록", notes = "새 보호 자원을 등록 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "이미 사용 중인 보호 자원 아이디 이거나, 허용되지 않는 정보가 있습니다."),
        ApiResponse(code = 403,message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun registerNewResource(@RequestBody registerRequest: SecuredResourceRegisterRequest) = service.registerNewResource(registerRequest)

    @PutMapping(value = ["/api/secured-resources/{resourceId}"])
    @ApiOperation(value = "보호 자원 수정", notes = "보호 자원을 수정 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "허용되지 않는 정보가 있습니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "등록되지 않은 보호 자원 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun modifyResource(
        @ApiParam(value = "보호 자원 아이디", required = true, example = "resource-id") @PathVariable resourceId: String,
        @RequestBody modifyRequest: SecuredResourceModifyRequest
    ) = service.modifyResource(resourceId, modifyRequest)

    @DeleteMapping(value = ["/api/secured-resources/{resourceId}"])
    @ApiOperation(value = "보호 자원 삭제", notes = "보호 자원을 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "등록되지 않은 보호 자원 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun removeResource(@ApiParam(value = "보호 자원 아이디", required = true, example = "resource-id") @PathVariable resourceId: String) =
        service.removeResource(resourceId)

    @ExceptionHandler(Exception::class)
    fun handle(e: Exception): ResponseEntity<ErrorMessage<Any>> = translator.translate(e)

}