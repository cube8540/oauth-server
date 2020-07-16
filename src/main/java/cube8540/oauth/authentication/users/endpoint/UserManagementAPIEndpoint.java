package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.users.application.UserManagementService;
import cube8540.oauth.authentication.users.application.UserProfile;
import cube8540.oauth.authentication.users.application.UserRegisterRequest;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
@Api(value = "유저 계정 관리 API 엔드 포인트")
public class UserManagementAPIEndpoint {

    private final UserManagementService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("userExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public UserManagementAPIEndpoint(UserManagementService service) {
        this.service = service;
    }

    @GetMapping(value = "/api/accounts/me")
    @ApiOperation(value = "계정 정보 검색", notes = "현재 로그인된 계정의 정보를 검색 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile getProfile(@AuthenticationPrincipal Authentication authentication) {
        return service.loadUserProfile(authentication.getName());
    }

    @DeleteMapping(value = "/api/accounts/me")
    @ApiOperation(value = "계정 삭제", notes = "현재 로그인된 계정을 삭제 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "잘못된 OAuth2 엑세스 토큰 입니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile removeProfile(@AuthenticationPrincipal Authentication authentication) {
        return service.removeUser(authentication.getName());
    }

    @PostMapping(value = "/api/accounts")
    @ApiOperation(value = "계정 등록", notes = "새 계정을 등록 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "요청하신 아이디가 중복 되었거나, 매개 변수의 형식이 옳바르지 않습니다."),
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile registerUserAccounts(@RequestBody UserRegisterRequest registerRequest) {
        return service.registerUser(registerRequest);
    }

    @GetMapping(value = "/api/accounts/attributes/username")
    @ApiOperation(value = "등록된 아이디 갯수 검색", notes = "매개 변수로 받은 아이디의 갯수를 검색 합니다. 주로 아이디 중복 검사에서 사용 합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 403, message = "로그인이 되어 있지 않습니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public Map<String, Long> countAccountUsername(@ApiParam(value = "검색할 아이디", required = true, example = "username1234") @RequestParam("username") String username) {
        long count = service.countUser(username);
        return Collections.singletonMap("count", count);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
