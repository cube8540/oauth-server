package cube8540.oauth.authentication.credentials.oauth.client.endpoint

import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ChangeSecretRequest
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientManagementService
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientModifyRequest
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientRegisterRequest
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails
import cube8540.oauth.authentication.error.ExceptionTranslator
import cube8540.oauth.authentication.error.message.ErrorMessage
import io.swagger.annotations.ApiImplicitParam
import io.swagger.annotations.ApiImplicitParams
import io.swagger.annotations.ApiOperation
import io.swagger.annotations.ApiParam
import io.swagger.annotations.ApiResponse
import io.swagger.annotations.ApiResponses
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.data.domain.Page
import org.springframework.data.domain.PageRequest
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
import java.lang.Exception
import java.util.*

@RestController
class ClientManagementAPIEndpoint @Autowired constructor(@Qualifier("defaultOAuth2ClientManagementService") private val service: OAuth2ClientManagementService) {

    companion object {
        private const val DEFAULT_CLIENT_PAGE_SIZE = 10
    }

    @set:[Autowired Qualifier("clientAPIExceptionTranslator")]
    lateinit var translator: ExceptionTranslator<ErrorMessage<Any>>

    var clientPageSize: Int = DEFAULT_CLIENT_PAGE_SIZE

    @GetMapping(value = ["/api/clients/attributes/clientId"])
    @ApiOperation(value = "클라이언트 아이디 갯수 검색", notes = "저장소에 저장된 클라이언트 아이디의 갯수를 검색 합니다. 주로 클라이언트 아이디 중복 검사에서 사용 합니다.")
    fun countClientId(@ApiParam(value = "클라이언트 아이디", required = true, example = "client-id") @RequestParam clientId: String): Map<String, Long> {
        val count = service.countClient(clientId)
        return Collections.singletonMap("count", count)
    }

    @GetMapping(value = ["/api/clients"])
    @ApiOperation(value = "등록된 클라이언트 검색", notes = "요청한 소유자에게 등록된 클라이언트를 모두 반환 합니다.")
    @ApiImplicitParams(value = [
        ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx"),
        ApiImplicitParam(value = "검색할 페이지 이며 0부터 시작 합니다. 입력 되지 않을시 0으로 설정 됩니다.", name = "page", example = "0"),
        ApiImplicitParam(value = "클라이언트 소유자", name = "owner", required = true, example = "username1234")
    ])
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun clients(@ApiParam(hidden = true) @RequestParam requestParameter: Map<String, String>): Page<OAuth2ClientDetails> {
        val page = requestParameter["page"]?.toInt() ?: 0
        val pageable = PageRequest.of(page, clientPageSize)

        return service.loadClientDetails(requestParameter["owner"]!!, pageable)
    }

    @PostMapping(value = ["/api/clients"])
    @ApiOperation(value = "새 클라이언트 등록", notes = "새 클라이언트를 저장소에 등록합니다. 등록된 클라이언트를 이용해 앞으로 OAuth2 토큰 발급을 할 수 있습니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "이미 사용중인 클라이언트 아이디 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun registerNewClient(@RequestBody registerRequest: OAuth2ClientRegisterRequest): OAuth2ClientDetails = service.registerNewClient(registerRequest)

    @GetMapping(value = ["/api/clients/{clientId}"])
    @ApiOperation(value = "클라이언트 정보 검색", notes = "요청한 클라이언트의 정보를 검색 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun client(@ApiParam(value = "검색할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable clientId: String): OAuth2ClientDetails =
        service.loadClientDetails(clientId)

    @PutMapping(value = ["/api/clients/{clientId}"])
    @ApiOperation(value = "클라이언트 수정", notes = "등록된 클라이언트를 수정 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "요청 정보중 허용 되지 않는 정보가 있습니다."),
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun modifyClient(
        @ApiParam(value = "수정할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable clientId: String,
        @RequestBody modifyRequest: OAuth2ClientModifyRequest
    ) = service.modifyClient(clientId, modifyRequest)

    @PutMapping(value = ["/api/clients/{clientId}/attributes/secret"])
    @ApiOperation(value = "클라이언트 패스워드 수정", notes = "등록된 클라이언트의 패스워드를 수정 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 400, message = "이전에 사용하던 패스워드와 일치하지 않습니다."),
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun changeSecret(
        @ApiParam(value = "수정할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable clientId: String,
        @RequestBody changeRequest: OAuth2ChangeSecretRequest
    ) = service.changeSecret(clientId, changeRequest)

    @DeleteMapping(value = ["/api/clients/{clientId}"])
    @ApiOperation(value = "클라이언트 삭제", notes = "등록된 클라이언트를 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = [
        ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
        ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
        ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
        ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    ])
    fun removeClient(@ApiParam(value = "삭제할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable clientId: String) =
        service.removeClient(clientId)

    @ExceptionHandler(Exception::class)
    fun handle(e: Exception): ResponseEntity<ErrorMessage<Any>> = translator.translate(e)

}