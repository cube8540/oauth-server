package cube8540.oauth.authentication.users.endpoint;

import cube8540.oauth.authentication.error.ExceptionTranslator;
import cube8540.oauth.authentication.error.message.ErrorMessage;
import cube8540.oauth.authentication.users.application.UserCredentialsService;
import cube8540.oauth.authentication.users.application.UserProfile;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Api(value = "유저 계정 인증 API 엔드 포인트")
public class UserCredentialsAPIEndpoint {

    private final UserCredentialsService service;

    @Setter(onMethod_ = {@Autowired, @Qualifier("userExceptionTranslator")})
    private ExceptionTranslator<ErrorMessage<Object>> translator;

    @Autowired
    public UserCredentialsAPIEndpoint(UserCredentialsService service) {
        this.service = service;
    }

    @PutMapping(value = "/api/accounts/attributes/active")
    @ApiOperation(value = "계정 활성화", notes = "처음 계정을 등록할 시 할당 받은 계정 활성화 키를 이용하여 계정을 활성화 시킵니다.")
    @ApiResponses(value = {
            @ApiResponse(code = 401, message = "키가 일치 하지 않거나, 만료 되었습니다."),
            @ApiResponse(code = 404, message = "요청 하신 유저는 등록 되지 않은 유저 입니다."),
            @ApiResponse(code = 500, message = "서버에서 알 수 없는 에러가 발생 했습니다.")
    })
    public UserProfile credentials(
            @ApiParam(value = "활성화 시킬 유저 아이디", required = true, example = "username1234") @RequestParam String username,
            @ApiParam(value = "계정 활성화 키", required = true, example = "xxxxxxxx") @RequestParam String credentialsKey) {
        return service.accountCredentials(username, credentialsKey);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessage<Object>> handle(Exception e) {
        return translator.translate(e);
    }
}
