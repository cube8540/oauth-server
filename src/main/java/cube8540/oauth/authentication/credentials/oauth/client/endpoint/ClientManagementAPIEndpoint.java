package cube8540.oauth.authentication.credentials.oauth.client.endpoint;

import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ChangeSecretRequest;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientManagementService;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientModifyRequest;
import cube8540.oauth.authentication.credentials.oauth.client.application.OAuth2ClientRegisterRequest;
import cube8540.oauth.authentication.credentials.oauth.security.OAuth2ClientDetails;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@Api(value = "OAuth2 클라이언트 관리 API 엔드 포인트")
public class ClientManagementAPIEndpoint {

    private static final int DEFAULT_CLIENT_PAGE_SIZE = 10;

    private final OAuth2ClientManagementService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("clientAPIExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Setter
    private int clientPageSize;

    @Autowired
    public ClientManagementAPIEndpoint(@Qualifier("defaultOAuth2ClientManagementService") OAuth2ClientManagementService service) {
        this.service = service;
        this.clientPageSize = DEFAULT_CLIENT_PAGE_SIZE;
    }

    @GetMapping(value = "/api/clients/attributes/clientId")
    @ApiOperation(value = "클라이언트 아이디 갯수 검색", notes = "저장소에 저장된 클라이언트 아이디의 갯수를 검색 합니다. 주로 클라이언트 아이디 중복 검사에서 사용 합니다.")
    public Map<String, Long> countClientId(@ApiParam(value = "클라이언트 아이디", required = true, example = "client-id") @RequestParam String clientId) {
        long count = service.countClient(clientId);
        return Collections.singletonMap("count", count);
    }

    @GetMapping(value = "/api/clients")
    @ApiOperation(value = "등록된 클라이언트 검색", notes = "로그인된 계정에 등록된 클라이언트를 모두 반환 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public Page<OAuth2ClientDetails> clients(
            @ApiParam(value = "검색할 페이지 이며 0부터 시작 합니다. 입력 되지 않을시 0으로 설정 됩니다.", example = "0") @RequestParam(value = "page", required = false) Integer page) {
        Pageable pageable = PageRequest.of(page == null ? 0 : page, clientPageSize);

        return service.loadClientDetails(pageable);
    }

    @PostMapping(value = "/api/clients")
    @ApiOperation(value = "새 클라이언트 등록", notes = "새 클라이언트를 저장소에 등록합니다. 등록된 클라이언트를 이용해 앞으로 OAuth2 토큰 발급을 할 수 있습니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "이미 사용중인 클라이언트 아이디 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public OAuth2ClientDetails registerNewClient(@RequestBody OAuth2ClientRegisterRequest registerRequest) {
        return service.registerNewClient(registerRequest);
    }

    @PutMapping(value = "/api/clients/{clientId}")
    @ApiOperation(value = "클라이언트 수정", notes = "등록된 클라이언트를 수정 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public OAuth2ClientDetails modifyClient(
            @ApiParam(value = "수정할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable("clientId") String clientId,
            @RequestBody OAuth2ClientModifyRequest modifyRequest) {
        return service.modifyClient(clientId, modifyRequest);
    }

    @PutMapping(value = "/api/clients/{clientId}/attributes/secret")
    @ApiOperation(value = "클라이언트 패스워드 수정", notes = "등록된 클라이언트의 패스워드를 수정 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "이전에 사용하던 패스워드와 일치하지 않습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public OAuth2ClientDetails changeSecret(
            @ApiParam(value = "수정할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable("clientId") String clientId,
            @RequestBody OAuth2ChangeSecretRequest changeRequest) {
        return service.changeSecret(clientId, changeRequest);
    }

    @DeleteMapping(value = "/api/clients/{clientId}")
    @ApiOperation(value = "클라이언트 삭제", notes = "등록된 클라이언트를 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "등록 되지 않은 클라이언트 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public OAuth2ClientDetails removeClient(
            @ApiParam(value = "삭제할 클라이언트 아이디", required = true, example = "oauth-id") @PathVariable("clientId") String clientId) {
        return service.removeClient(clientId);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}