# 토큰 부여 API
권한 서버로 부터 인증을 받고 토큰을 부여 받는 API 입니다.

## 구현되어 있는 인증 타입
[Authorization Code](#authorization-code-flow)  
[Implicit](#implicit-flow)  
[Resource Owner Password Credentials (Password)](#resource-owner-password-credentials-flow)  
[Client Credentials](#client-credentials-flow)  
[Refresh Token](#refresh-token-flow)  

## 에러
[에러 코드](#에러-코드)

### Authorization Code Flow
OAuth2에서 가장 많이 볼 수 있는 인증 유형 입니다. 클라이언트가 직접 자원 소유자에게 권한을 부여하며 자원 소유자는 권한 서버에 인증을 받고
인가를 허용 합니다. 자원 소유자가 인가를 허용하게 되면 권한 코드가 발급되며, 이 권한 코드를 클라이언트에 전달합니다. 클라이언트는 받은
권한 코드를 권한 서버에 보내주어 Access Token 을 발급 받습니다.
#### 자원 소유자 인증
자원 소유자의 인증을 위해 브라우저를 키고 아래의 주소로 이동합니다.
```
http://localhost:8080/oauth/authorize?response_type=code
&redirect_uri=http://example-your-app.com/callback
&client_id=<your-client-id>
```
|  파라미터명    |  필수 여부     |  타입   |  설명  |
| :-----------:   | :--------------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| response_type | Required       | String | 응답 타입 받드시 **code** 이어야 합니다.                                                                         |
| redirect_uri  | Optional       | URI    | 인가 코드를 받을 URI. 클라이언트에 등록된 URI가 여러개면 필수로 포함되어야 합니다.                                  |
| client_id     | Required       | String | 클라이언트 아이디                                                                                               |
| state         | Optional(권장) | String | CSRF 토큰 역할을 합니다. 만약 state 값에 대한 검증이 누락 되었거나 미흡하면 사용자 계정을 탈취 당할 수 있습니다.     |
| scope         | Optional       | String | 인증 후 얻을 스코프 입니다. 스코프는 여러개를 요청할 수 있으며 공백으로 구별 합니다. 생략될시 모든 스코프를 얻습니다. |

위 요청을 하면 권한 서버는 자원 소유자의 인증을 위해 인증 페이지로 리다이렉트 하게 됩니다. 이후 자원 소유자가 인증을 완료하고
인가를 허락할시 /oauth/authorize 를 요청 할 때 이용한 **redirect_uri**로 **code** 를 전달 합니다.
```
http://example-your-app.com/callback?code=xxxxxxx
```
|  파라미터명    |  타입   |  설명                     |
| :-----------:   | :-----:  | -------------------------- |
| code          | String | 인가 코드                   |
| state         | String | 이전 요청에서 보낸 state 값 |
#### Access Token 교환
위의 과정에서 얻은 **code**를 다시 권한 서버로 보내 Access Token 을 얻어 옵니다.
```
POST HTTP/1.1
http://localhost:8080/oauth/token?grant_type=authorization_code
&code=<your-authorization-code>
&redirect_uri=http://example-your-app.com/callback
&client_id=<your-client-id>
&client_secret=<your-client-secret>
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------:   | :---------: | :-----:  | --------------------------------------------------------------- |
| grant_type    | Required  | String | 인가 타입으로 반드시 **authorization_code** 이어야 합니다.        |
| code          | Required  | String | 권한 서버로 부터 받은 인가 코드                                   |
| redirect_uri  | Optional  | URI    | /oauth/authorize 호출시 입력 되었던 리다이렉트 URI 입니다.        |
| client_id     | Optional  | String | 클라이언트 아이디. BasicAuth 사용시 생략될 수 있습니다.            |
| client_secret | Optional  | String | 클라이언트 패스워드. BasicAuth 사용시 생략될 수 있습니다.          |
| state         | Optional  | String | 권한 서버로 부터 받은 state 값. 받지 않았을시 생략 할 수 있습니다. |
| scope         | Optional  | String | /oauth/authorize 호출시 입력 되었던 스코프 입니다.               |

위 요청을 통해 아래와 같이 Access Token 을 발급 받을 수 있습니다.
```json
{
    "access_token": "5f169a5a1c6d49d5a0eb7884b4428121",
    "token_type": "Bearer",
    "expires_in": 599,
    "scope": "TEST-2 TEST-3 TEST-1 TEST-4",
    "refresh_token": "fe36c27cbc104eaeb100c17b000d3613"
}
```
### Implicit Flow
이 방식은 Authorization Code Flow 에서 인증 코드와 Access Token 의 교환 과정을 생략하고 바로 Access Token 을 가져오는 방식 입니다.
주로 자바스크립트 어플리케이션 ex) SPA.. 및 특정한 저장 장소가 없는 어플리케이션 에서 주로 사용하며, 보안이 좋지 않아 권장하지 않는 방식 입니다.
#### 자원 소유자 인증
Authorization Code Flow 와 마찬 가지로 자원 소유자의 인증을 위해 브라우저를 키고 아래의 주소로 이동합니다.
```
http://localhost:8080/oauth/authorize?response_type=code
&redirect_uri=http://example-your-app.com/callback
&client_id=<your-client-id>
```
|  파라미터명    |  필수 여부     |  타입   |  설명  |
| :-----------:   | :--------------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| response_type | Required       | String | 응답 타입 받드시 **code** 이어야 합니다.                                                                         |
| redirect_uri  | Optional       | URI    | 인가 코드를 받을 URI. 클라이언트에 등록된 URI가 여러개면 필수로 포함되어야 합니다.                                  |
| client_id     | Required       | String | 클라이언트 아이디                                                                                               |
| state         | Optional(권장) | String | CSRF 토큰 역할을 합니다. 만약 state 값에 대한 검증이 누락 되었거나 미흡하면 사용자 계정을 탈취 당할 수 있습니다.     |
| scope         | Optional       | String | 인증 후 얻을 스코프 입니다. 스코프는 여러개를 요청할 수 있으며 공백으로 구별 합니다. 생략될시 모든 스코프를 얻습니다. |

위 요청을 하면 권한 서버는 자원 소유자의 인증을 위해 인증 페이지로 리다이렉트 하게 됩니다. 이후 자원 소유자가 인증을 완료하고
인가를 허락할시 /oauth/authorize 를 요청 할 때 이용한 **redirect_uri**로 **Access Token** 를 전달 합니다.
```
http://example-your-app.com/callback#access_token=5f169a5a1c6d49d5a0eb7884b4428121
&token_type=Bearer
&expires_in=599
&scope=TEST-2 TEST-3 TEST-1 TEST-4
```
### Resource Owner Password Credentials Flow
자원 소유자가 직접 아이디와 패스워드를 입력하여 권한 서버에 인증을 받습니다. 클라이언트는 입력 받은 자원 소유자의 아이디와
패스워드를 권한 서버로 보내 자원 소유자에게 엑세스 토큰을 부여 합니다.
#### Access Token 발급
```
POST HTTP/1.1
http://localhost:8080/oauth/token?grant_type=password
&username=<resource-owner-username>
&password=<resource-owner-password>
&client_id=<your-client-id>
&client_secret=<your-client-secret>
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------:   | :---------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| grant_type    | Required  | String | 인가 타입으로 반드시 **password** 이어야 합니다.                                                                 |
| client_id     | Optional  | String | 클라이언트 아이디. BasicAuth 사용시 생략될 수 있습니다.                                                           |
| client_secret | Optional  | String | 클라이언트 패스워드. BasicAuth 사용시 생략될 수 있습니다.                                                         |
| username      | Required  | String | 자원 소유자의 아이디                                                                                            |
| password      | Required  | String | 자원 소유자의 패스워드                                                                                          |
| scope         | Optional  | String | 인증 후 얻을 스코프 입니다. 스코프는 여러개를 요청할 수 있으며 공백으로 구별 합니다. 생략될시 모든 스코프를 얻습니다. |

위 요청으로 아래와 같이 Access Token 을 발급 받을 수 있습니다.
```json
{
    "access_token": "c63e50a88f634bf09bcd86f9fed3f08c",
    "token_type": "Bearer",
    "expires_in": 599,
    "scope": "TEST-2 TEST-3 TEST-1 TEST-4",
    "refresh_token": "9e0b4f464eb94e72bdfeb849c78f3b95"
}
```
### Client Credentials Flow
클라이언트가 외부에서 Access Token 을 부여받아 특정 자원 서버에 접근을 요청할 때 사용하는 방식 입니다. 클라이언트의 아이디와
패스워드를 권한 서버로 보내 클라이언트에게 Access Token 을 발급 합니다.
#### Access Token 발급
```
POST HTTP/1.1
http://localhost:8080/oauth/token?grant_type=client_credentials
&client_id=<your-client-id>
&client_secret=<your-client-secret>
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------:   | :---------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| grant_type    | Required  | String | 인가 타입으로 반드시 **client_credentials** 이어야 합니다.                                                       |
| client_id     | Optional  | String | 클라이언트 아이디. BasicAuth 사용시 생략될 수 있습니다.                                                           |
| client_secret | Optional  | String | 클라이언트 패스워드. BasicAuth 사용시 생략될 수 있습니다.                                                         |
| scope         | Optional  | String | 인증 후 얻을 스코프 입니다. 스코프는 여러개를 요청할 수 있으며 공백으로 구별 합니다. 생략될시 모든 스코프를 얻습니다. |

위 요청으로 아래와 같이 Access Token 을 발급 받을 수 있습니다.
```json
{
    "access_token": "78efb01d6df8400095d12c8c5041cfa4",
    "token_type": "Bearer",
    "expires_in": 599,
    "scope": "TEST-2 TEST-3 TEST-1 TEST-4"
}
```
현재 Client Credentials Flow 에는 리플래시 토큰을 발급 하지 않도록 구현 했습니다.
### Refresh Token Flow
Access Token 을 부여 받을시 Refresh Token 을 부여 받았다면 부여 받은 Refresh Token 으로 새로운 Access Token 을 간단히
재발급 받을 수 있습니다. 클라이언트는 Refresh Token 을 권한 서버로 보내 새 Access Token 을 발급 받아 자원 소유자에게 부여 합니다.
#### Access Token 재발급
```
POST HTTP/1.1
http://localhost:8080/oauth/token?grant_type=refresh_token
&refresh_token=<your-refresh-token>
&client_id=<your-client-id>
&client_secret=<your-client-secret>
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------:   | :---------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| grant_type    | Required  | String | 인가 타입으로 반드시 **refresh_token** 이어야 합니다.                                                            |
| refresh_token | Required  | String | 발급 받은 Refresh Token                                                                                         |
| client_id     | Optional  | String | 클라이언트 아이디. BasicAuth 사용시 생략될 수 있습니다.                                                           |
| client_secret | Optional  | String | 클라이언트 패스워드. BasicAuth 사용시 생략될 수 있습니다.                                                         |
| scope         | Optional  | String | 인증 후 얻을 스코프 입니다. 스코프는 여러개를 요청할 수 있으며 공백으로 구별 합니다. 기존의 스코프를 얻습니다.        |

위 요청으로 아래와 같이 Access Token 을 발급 받을 수 있습니다.
```json
{
    "access_token": "345ef233f52d4fc6be496b9983014821",
    "token_type": "Bearer",
    "expires_in": 599,
    "scope": "TEST-2 TEST-3 TEST-1 TEST-4",
    "refresh_token": "df0dd0336f434b0da30e4c4da3c7c4e8"
}
```
현재 Refresh Token 을 통해 Access Token 을 재발급 받을시 기존의 Access Token과 Refresh Token은 삭제되도록 구현 했습니다.

## 에러 코드
OAuth2 토큰을 발급 받는 도중에 에러가 발생하거나 잘못된 요청이 들어올시 아래와 같은 메시지가 반환 됩니다.
```json
{
    "error": "invalid_grant",
    "error_description": "invalid refresh token"
}
```
현재 사용중인 에러 코드와 HTTP 상태 코드는 아래와 같습니다.

|              에러 코드              | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | ---------------------------------------------------------------------------- |
| invalid_request                    |    400    | 필수로 지정된 매개변수가 입력되지 않았거나 잘못 되었음을 알리는 에러 코드 입니다. |
| unsupported_response_type          |    400    | 지원되지 않는 response_type 임을 알리는 에러 코드 입니다.                      |
| invalid_grant                      |    400    | 어떠한 이유로 토큰을 부여 할 수 없음을 알리는 에러 코드 입니다.                 |
| invalid_scope                      |    400    | 입력하신 스코프가 잘못 되었음을 알리는 에러 코드 입니다.                        |
| unsupported_grant_type             |    400    | 지원되지 않는 인증 타입임을 알리는 에러 코드 입니다.                            |
| invalid_client                     |    401    | 잘못된 클라이언트임을 알리는 에러 코드 입니다.                                 |
| unauthorized_client                |    401    | 인증 받지 못한 혹은 인증에 실패한 클라이언트임을 알리는 에러 코드 입니다.        |
| access_denied                      |    403    | 자원 소유자가 접근을 거부했음을 알리는 에러 코드 입니다.                        |
| server_error                       |    500    | 서버에서 에러가 났음을 알리는 에러 코드 입니다.                                |
