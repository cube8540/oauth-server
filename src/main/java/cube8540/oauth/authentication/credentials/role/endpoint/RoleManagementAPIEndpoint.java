package cube8540.oauth.authentication.credentials.role.endpoint;

import cube8540.oauth.authentication.credentials.AuthorityDetails;
import cube8540.oauth.authentication.credentials.role.application.RoleManagementService;
import cube8540.oauth.authentication.credentials.role.application.RoleModifyRequest;
import cube8540.oauth.authentication.credentials.role.application.RoleRegisterRequest;
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
import java.util.List;
import java.util.Map;

@RestController
@Api(value = "권한 관리 API 엔드 포인트")
public class RoleManagementAPIEndpoint {

    private final RoleManagementService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("roleExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public RoleManagementAPIEndpoint(RoleManagementService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/authorities")
    @ApiOperation(value = "등록된 권한 검색", notes = "저장소에 등록된 권한을 모두 검색한다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public Map<String, Collection<AuthorityDetails>> authorities() {
        List<AuthorityDetails> authorities = service.loadAllAuthorities();
        return Collections.singletonMap("authorities", authorities);
    }

    @PostMapping(value = "/api/authorities")
    @ApiOperation(value = "새 권한 등록", notes = "저장소에 새 권한을 등록 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "이미 사용중인 권한 코드 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public AuthorityDetails registerNewRole(@RequestBody RoleRegisterRequest request) {
        return service.registerNewRole(request);
    }

    @PutMapping(value = "/api/authorities/{roleCode}")
    @ApiOperation(value = "권한 수정", notes = "권한의 정보를 수정 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "이미 사용중인 권한 코드 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 권한은 등록 되지 않은 권한 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public AuthorityDetails modifyRole(
            @ApiParam(value = "권한 코드", required = true, example = "ROEL_USER") @PathVariable("roleCode") String roleCode,
            @RequestBody RoleModifyRequest modifyRequest) {
        return service.modifyRole(roleCode, modifyRequest);
    }

    @DeleteMapping(value = "/api/authorities/{roleCode}")
    @ApiOperation(value = "권한 삭제", notes = "저장소에서 권한을 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "이미 사용 중인 권한 코드 이거나, 요청 정보중 허용 되지 않는 정보가 있습니다."),
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 권한은 등록 되지 않은 권한 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public AuthorityDetails removeRole(@ApiParam(value = "권한 코드", required = true, example = "ROEL_USER") @PathVariable("roleCode") String roleCode) {
        return service.removeRole(roleCode);
    }

    @GetMapping(value = "/api/authorities/attributes/code")
    @ApiOperation(value = "권한 코드 갯수 검색", notes = "저장소에 저장된 권한 코드의 갯수를 검색 합니다. 주로 권한 코드 중복 검사에서 사용 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    public Map<String, Long> countRoleCode(@ApiParam(value = "권한 코드", required = true, example = "ROEL_USER") @RequestParam String code) {
        Long count = service.countByRoleCode(code);

        return Collections.singletonMap("count", count);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
