package cube8540.oauth.authentication.credentials.oauth.scope.endpoint;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2AccessibleScopeDetailsService;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeManagementService;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeModifyRequest;
import cube8540.oauth.authentication.credentials.oauth.scope.application.OAuth2ScopeRegisterRequest;
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
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@RestController
@Api(value = "OAuth2 스코프 관리 API 엔드 포인트")
public class ScopeManagementAPIEndpoint {

    private final OAuth2ScopeManagementService managementService;
    private final OAuth2AccessibleScopeDetailsService accessibleScopeDetailsService;

    @Setter(onMethod_ = {@Autowired, @Qualifier("scopeExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public ScopeManagementAPIEndpoint(OAuth2ScopeManagementService managementService, OAuth2AccessibleScopeDetailsService accessibleScopeDetailsService) {
        this.managementService = managementService;
        this.accessibleScopeDetailsService = accessibleScopeDetailsService;
    }

    @GetMapping(value = "/api/scopes")
    @ApiOperation(value = "등록된 스코프 검색", notes = "로그인된 계정이 접근 할 수 있는 스코프를 검색 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public Map<String, Collection<AuthorityDetails>> scopes(@AuthenticationPrincipal Authentication authentication) {
        Collection<AuthorityDetails> scopes = accessibleScopeDetailsService.readAccessibleScopes(authentication);

        return Collections.singletonMap("scopes", scopes);
    }

    @PostMapping(value = "/api/scopes")
    @ApiOperation(value = "새 스코프 등록", notes = "새 스코프를 등록 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "이미 사용중인 스코프 아이디 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 스코프는 등록 되지 않은 스코프 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public AuthorityDetails registerNewScopes(@RequestBody OAuth2ScopeRegisterRequest registerRequest) {
        return managementService.registerNewScope(registerRequest);
    }

    @PutMapping(value = "/api/scopes/{id}")
    @ApiOperation(value = "스코프 수정", notes = "스코프의 정보를 변경 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 스코프는 등록 되지 않은 스코프 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public AuthorityDetails modifyScope(@PathVariable("id") String id, @RequestBody OAuth2ScopeModifyRequest modifyRequest) {
        return managementService.modifyScope(id, modifyRequest);
    }

    @DeleteMapping(value = "/api/scopes/{id}")
    @ApiOperation(value = "스코프 삭제", notes = "스코프를 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 스코프는 등록 되지 않은 스코프 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public AuthorityDetails removeScope(@PathVariable("id") String id) {
        return managementService.removeScope(id);
    }

    @GetMapping(value = "/api/scopes/attributes/scopeId")
    @ApiOperation(value = "스코프 아이디 갯수 검색", notes = "매개 변수로 받은 스코프의 갯수를 검색 합니다. 주로 스코프 중복 검사에서 사용 합니다.")
    public Map<String, Long> countScopeId(@ApiParam(value = "스코프 아이디", required = true, example = "scope") @RequestParam String scopeId) {
        Long count = managementService.countByScopeId(scopeId);

        return Collections.singletonMap("count", count);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
