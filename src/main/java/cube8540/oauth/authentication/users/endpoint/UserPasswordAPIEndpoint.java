package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.users.application.ChangePasswordRequest;
import cube8540.oauth.authentication.users.application.ResetPasswordRequest;
import cube8540.oauth.authentication.users.application.UserPasswordService;
import cube8540.oauth.authentication.users.application.UserProfile;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@Api(value = "유저 패스워드 관리 API 엔드 포인트")
public class UserPasswordAPIEndpoint {

    private final UserPasswordService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("userExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public UserPasswordAPIEndpoint(UserPasswordService service) {
        this.service = service;
    }

    @PutMapping(value = "/api/accounts/attributes/password")
    @ApiOperation(value = "계정 패스워드 변경", notes = "현재 로그인된 계정의 패스워드를 변경합니다.")
    @ApiImplicitParam(value = "OAuth2 엑세스 토큰", name = "Authorization", required = true, paramType = "header", example = "Bearer xxxxxxxxxx")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "변경하려는 패스워드가 유효하지 않습니다."),
            @ApiResponse(code = 401, message = "OAuth2 토큰이 잘못 되었거나, 변경 전 사용하던 패스워드가 일치하지 않습니다."),
            @ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile changePassword(Principal principal, @RequestBody ChangePasswordRequest changeRequest) {
        return service.changePassword(principal, changeRequest);
    }

    @DeleteMapping(value = "/api/accounts/attributes/password")
    @ApiOperation(value = "패스워드를 분실", notes = "패스워드를 분실한 계정에 패스워드 초기화 키를 할당합니다. 해당 요청 이후에도 로그인은 가능 합니다.")
    @ApiResponses(value = {
            @ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile forgotPassword(@ApiParam(value = "패스워드를 분실한 유저의 아이디", required = true) @RequestParam String username) {
        return service.forgotPassword(username);
    }

    @PostMapping(value = "/api/accounts/attributes/password")
    @ApiOperation(value = "패스워드 초기화", notes = "패스워드 초기화 키를 사용하여 계정의 패스워드를 초기화 합니다.")
    @ApiResponses(value = {
            @ApiResponse(code = 400, message = "변경하려는 패스워드가 유효하지 않습니다."),
            @ApiResponse(code = 401, message = "패스워드 초기화 키가 일치 하지 않거나 만료 되었습니다."),
            @ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
        return service.resetPassword(resetPasswordRequest);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
