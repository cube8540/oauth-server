# OAuth2 권한 서버

Spring Boot + Spring Security 를 이용하여 구현한 OAuth2 권한 서버 입니다. 

## 구현되어 있는 인증 타입
- [Authorization Code](#authorization-code-flow)
- [Resource Owner Password Credentials (Password)](#resource-owner-password-credentials-flow)
- [Client Credentials](#client-credentials-flow)
- [Refresh Token](#refresh-token-flow)

위의 네가지 인증 타입을 구현하였으며 Implicit 인증 타입은 현재 구현되어 있지 않습니다. 아래는 각 인증 타입의 Access Token 을 얻는 과정 입니다.
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
## 에러
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

---

# HTTP API
OAuth2 토큰 발급에 관련되어 있지 않은 API 입니다. 아래의 API를 이용하여 OAuth2 클라이언트 추가 및 수정, 유저 등록 등을 할 수 있습니다.

## 계정 HTTP API
저장소에 계정을 추가 하거나 변경하는 HTTP API 입니다. 계정의 패스워드 변경을 제외하고는 모두 로그인을 하지 않고 호출 할 수 있습니다.
아래는 현재 구현된 계정 HTTP API 리스트 입니다.
- [새 계정 등록](#새-계정-등록)
- [등록된 이메일 갯수 검색](#저장소에-등록된-이메일-갯수-검색)
- [패스워드 초기화키 할당](#패스워드-초기화키-할당)
- [패스워드 변경](#패스워드-변경)
- [패스워드 초기화](#패스워드-초기화)
- [계정 활성화](#계정-활성화)

### 새 계정 등록
저장소에 새 계정을 등록하고 계정 활성화 키를 할당 합니다. 처음 계정이 등록 되었을땐 계정은 비 활성화 상태 임으로 로그인을 할 수 없습니다.
로그인을 하기 위해서는 아래의 계정 활성화 API를 이용하여 계정을 활성화 해야 합니다. 

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/accounts

X-CSRF-TOKEN: 03eacf13-6f4a-4ea5-8d63-ae2fb0b39f06

{
    "email": "email@email.com",
    "password": "Password1234!@#$"
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------ |
| email         | Required  | String | 등록할 유저의 이메일 이며 중복될 수 없습니다. |
| password      | Required  | String | 등록할 유저의 패스워드                      |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "email": "email@email.com",
    "registeredAt": null
}

```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| email         | String | 등록된 유저의 이메일 |
| registeredAt  | String | 등록된 유저의 가입일 |

#### 에러
```
HTTP/1.1 400
Content-Type: application/json

{
    "errorCode": "exists_identifier",
    "description": "email@email.com is exists"
}
```
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| exists_identifier                    |    400    | 요청하신 이메일이 이미 사용중임을 알리는 에러 코드 입니다.                     |
| invalid_request                      |    400    | 요청하신 이메일 혹은 패스워드의 형식이 유효하지 않음을 알리는 에러 코드 입니다. |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 저장소에 등록된 이메일 갯수 검색
저장소에 저장된 이메일을 갯수를 검색합니다. 주로 이메일 중복 여부를 확인할 때 사용 합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/accounts/attributes/email
?email=email@email.com
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------ |
| email         | Required  | String | 검색할 이메일 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "count": 1
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| count         | Number | 등록된 이메일의 갯수 |

### 패스워드 초기화키 할당
패스워드 초기화를 위해 계정에 패스워드 초기화 키를 할당 합니다. 주로 패스워드를 분실 하였을시 사용합니다. 해당 요청 이후에도
로그인은 가능 합니다.

#### 요청
```
DELETE HTTP/1.1
http://localhost:8080/api/accounts/attribute/password
?email=email@email.com

X-CSRF-TOKEN: 03eacf13-6f4a-4ea5-8d63-ae2fb0b39f06
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------ |
| email         | Required  | String | 패스워드를 분실하거나 초기화 할 이메일 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "email": "email@email.com",
    "registeredAt": "2020-01-31T15:10:07"
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| email         | String | 변경된 유저의 이메일 |
| registeredAt  | String | 변경된 유저의 가입일 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "email@email.com1 user not found"
}
```
|        에러 코드             | 상태 코드 |                                   설명                                      |
| :--------------------------: | :---------: | ------------------------------------------------------------------------ |
| not_found                    |    404    | 요청하신 이메일을 가진 유저를 저장소에서 찾을 수 없을 알리는 에러 코드 입니다. |
| server_error                 |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 패스워드 변경
로그인한 유저의 패스워드를 변경 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/accounts/attributes/password

X-CSRF-TOKEN: 03eacf13-6f4a-4ea5-8d63-ae2fb0b39f06

{
    "existingPassword": "Password1234!@#$",
    "newPassword": "NewPassword1234!@#$"
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------ |
| existingPassword | Required  | String | 변경전 사용하던 패스워드 |
| newPassword      | Required  | String | 변경할 패스워드 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "email": "email@email.com",
    "registeredAt": "2020-01-31T15:10:07"
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| email         | String | 변경된 유저의 이메일 |
| registeredAt  | String | 변경된 유저의 가입일 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "email@email.com1 user not found"
}
```
|        에러 코드             | 상태 코드 |                                   설명                                      |
| :--------------------------: | :---------: | ------------------------------------------------------------------------ |
| invalid_request             |    400    | 변경하려는 패스워드가 유효하지 않음을 알리는 에러 코드 입니다.                 |
| invalid_password             |    401    | 변경전 사용하던 패스워드가 일치하지 않음을 알리는 에러 코드 입니다.            |
| not_found                    |    404    | 요청하신 이메일을 가진 유저를 저장소에서 찾을 수 없을 알리는 에러 코드 입니다. |
| server_error                 |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 패스워드 초기화
패스워드 초기화 키를 이용하여 계정의 패스워드를 새로 할당합니다. 주로 패스워드 분실 후 할당 받은 패스워드 키로 패스워드를 초기화 하는데 사용 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/accounts/attributes/password

X-CSRF-TOKEN: 03eacf13-6f4a-4ea5-8d63-ae2fb0b39f06

{
    "email": "email@email.com",
    "credentialsKey": "xxxxxxxxxxxxxx",
    "newPassword": "NewPassword1234!@#$"
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------- |
| email         | Required  | String | 패스워드를 초기화 할 이메일 |
| credentialsKey| Required  | String | 패스워드 초기화 키 |
| newPassword   | Required  | String | 변경할 패스워드 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "email": "email@email.com",
    "registeredAt": "2020-01-31T15:10:07"
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| email         | String | 변경된 유저의 이메일 |
| registeredAt  | String | 변경된 유저의 가입일 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "email@email.com1 user not found"
}
```
|        에러 코드             | 상태 코드 |                                   설명                                      |
| :--------------------------: | :---------: | ------------------------------------------------------------------------ |
| invalid_request             |    400    | 변경하려는 패스워드가 유효하지 않음을 알리는 에러 코드 입니다.                  |
| invalid_key                   |    401    | 패스워드 초기화 키가 일치하지 않음을 알리는 에러 코드 입니다.                 |
| key_expired                   |    401    | 패스워드 초기화 키가 만료되었음을 알리는 에러 코드 입니다.                    |
| not_found                    |    404    | 요청하신 이메일을 가진 유저를 저장소에서 찾을 수 없을 알리는 에러 코드 입니다.  |
| server_error                 |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 계정 활성화
처음 계정을 등록할 시 할당 받은 계정 활성화 키를 이용하여 계정을 활성화 시키고 기본 권한을 할당 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/accounts/attributes/active
?credentialsKey=xxxxxxxxxxx

X-CSRF-TOKEN: 03eacf13-6f4a-4ea5-8d63-ae2fb0b39f06
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | --------------- |
| credentialsKey| Required  | String | 계정 활성화 키 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "email": "email@email.com",
    "registeredAt": "2020-01-31T15:10:07"
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| email         | String | 활성화된 유저의 이메일 |
| registeredAt  | String | 활성화된 유저의 가입일 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "email@email.com1 user not found"
}
```
|        에러 코드             | 상태 코드 |                                   설명                                       |
| :--------------------------: | :---------: | ------------------------------------------------------------------------- |
| invalid_key                   |    401    | 활성화 키가 일치하지 않음을 알리는 에러 코드 입니다.                          |
| key_expired                   |    401    | 활성화 키가 만료되었음을 알리는 에러 코드 입니다.                             |
| not_found                    |    404    | 요청하신 이메일을 가진 유저를 저장소에서 찾을 수 없을 알리는 에러 코드 입니다.  |
| server_error                 |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

## 권한 HTTP API
새 권한을 추가하거나 삭제, 수정하는 HTTP API 입니다. 관리자 권한을 가진 계정으로 로그인 했을시만 접근 할 수 있도록 설정 해야 합니다.
아래는 현재 구현된 권한 HTTP API 리스트 입니다.

- [새 권한 등록](#새-권한-등록)
- [모든 권한 검색](#저장된-모든-권한-검색)
- [권한 정보 변경](#권한-정보-변경)
- [권한 삭제](#권한-삭제)
- [저장된 권한 코드 갯수 검색](#권한-코드-갯수-검색)

### 새 권한 등록
저장소에 새 권한을 등록 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/authorities

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "code": "TEST-ROLE"
    "description": "테스트 권한"
    "basic": true
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | -------------------------------------------------- |
| code         | Required  | String | 추가할 권한 코드                                     |
| description  | Required  | String | 권한의 설명 텍스트                                   |
| basic        | Required  | Boolean | 기본 권한 여부로 true 일시 기본 권한으로 설정 됩니다. |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "code": "TEST-ROLE",
    "description": "테스트 권한",
    "basic": true
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| code         | String | 추가된 권한 코드        |
| description  | String |추가된 권한의 설명 텍스트 |
| basic  | Boolean |추가된 권한의 기본 권한 여부 |

#### 에러
```
HTTP/1.1 400
Content-Type: application/json

{
    "errorCode": "exists_identifier",
    "description": "email@email.com is exists"
}
```
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| exists_identifier                    |    400    | 요청하신 권한 코드가 이미 사용중임을 알리는 에러 코드 입니다.                  |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 저장된 모든 권한 검색
저장소에 저장된 모든 권한을 검색 합니다.

#### 요청
```
GET HTTP/1.1

http://localhost:8080/api/authorities
```

### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "authorities": [
        {
            "code": "ROLE_USER",
            "description": "테스트용 기본 권한",
            "basic": true
        }
    ]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| authorities  | Array  | 검색된 권한 리스트      |
| code         | String | 권한 코드               |
| description  | String | 권한의 설명 텍스트      |
| basic  | Boolean | 권한의 기본 권한 여부      |

### 권한 정보 변경
권한의 정보를 변경 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/authorities/{code=TEST-ROLE}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "description": "변경된 설명 텍스트",
    "basic": true
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | -------------------------------------------------- |
| code         | Required  | String | 변경할 권한 코드                                     |
| description  | Required  | String | 권한의 설명 텍스트                                   |
| basic        | Required  | Boolean | 기본 권한 여부로 true 일시 기본 권한으로 설정 됩니다. |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "code": "TEST-ROLE",
    "description": "변경된 설명 텍스트",
    "basic": true
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| code         | String | 변경된 권한 코드        |
| description  | String | 변경된 권한의 설명 텍스트 |
| basic  | Boolean | 변경된 권한의 기본 권한 여부 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "TEST-ROLE is not found"
}
```
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| not_found                            |    404    | 요청하신 권한을 찾을 수 없음을 알리는 에러 코드 입니다.                       |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.               |

### 권한 삭제
권한을 삭제 합니다.

#### 요청
```
DELETE HTTP/1.1
http://localhost:8080/api/authorities/{code=TEST-ROLE}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | -------------------------------------------------- |
| code         | Required  | String | 삭제할 권한 코드                                     |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "code": "TEST-ROLE",
    "description": "권한 설명 텍스트",
    "basic": true
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| code         | String | 삭제된 권한 코드        |
| description  | String | 삭제된 권한의 설명 텍스트 |
| basic  | Boolean | 삭제된 권한의 기본 권한 여부 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "TEST-ROLE is not found"
}
```
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| not_found                            |    404    | 요청하신 권한을 찾을 수 없음을 알리는 에러 코드 입니다.                       |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.               |

### 권한 코드 갯수 검색
권한 코드의 갯수를 검색 합니다. 주로 권한 코드의 중복 여부를 확인할 때 사용 합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/authorities/attributes/code
?code=xxxxxxxxxx
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | -------------- |
| code         | Required  | String | 검색할 권한 코드 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "count": 1
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| count         | Number | 등록된 권한 코드의 갯수 |

## OAuth2 클라이언트 HTTP API
로그인한 계정의 OAuth2 클라이언트를 검색 하거나 추가, 수정 합니다. 아래는 현재 구현된 OAuth2 클라이언트 HTTP API 리스트 입니다.

- [새 클라이언트 등록](#새-클라이언트-등록)
- [등록된 클라이언트 검색](#등록된-클라이언트-검색)
- [클라이언트 정보 변경](#클라이언트-정보-변경)
- [클라이언트 삭제](#클라이언트-삭제)
- [클라이언트 패스워드 변경](#클라이언트-패스워드-변경)
- [저장된 클라이언트 갯수 검색](#클라이언트-아이디-갯수-검색)

### 새 클라이언트 등록
새 클라이언트를 저장소에 등록합니다. 등록된 클라이언트를 이용해 앞으로 OAuth2 토큰 발급을 할 수 있습니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/clients

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "clientId": "CLIENT-ID",
    "secret": "CLIENT-SECRET",
    "clientName":   "CLIENT-NAME",
    "redirectUris": ["http://localhost:8080/callback", "http://localhost:8081/callback"],
    "scopes": ["TEST-1", "TEST-2", "TEST-3"],
    "grantTypes": ["authorization_code", "refresh_token", "client_credentials"]
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | -------------------------------------------------- |
| clientId      | Required  | String | 추가할 클라이언트의 아이디                           |
| clientSecret  | Required  | String | 추가할 클라이언트의 패스워드                          |
| clientName    | Required  | String | 추가할 클라이언트의 이름                             |
| redirectUris  | Required  | Array  | Authorization Code 인증에서 사용할 리다이렉트 URI    |
| scopes        | Required  | Array  | 이 클라이언트로 부여 받을 수 있는 스코프             |
| grantTypes    | Required  | Array  | 클라이언트가 제공하는 인증 방식                     |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "clientId": "CLIENT-ID",
    "clientName": "CLIENT-NAME",
    "registeredRedirectUris": [
        "http://localhost:8080/callback",
        "http://localhost:8081/callback"
    ],
    "authorizedGrantTypes": [
        { "value": "refresh_token" },
        { "value": "client_credentials" },
        { "value": "authorization_code" }
    ],
    "scopes": ["TEST-3", "TEST-1", "TEST-2"],
    "owner": "email@email.com",
    "accessTokenValiditySeconds": 600,
    "refreshTokenValiditySeconds": 7200
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| clientId                    | String | 등록된 클라이언트의 아이디                       |
| clientName                  | String | 등록된 클라이언트의 이름                         |
| registeredRedirectURI       | Array  | 등록된 클라이언트의 리다이렉트 URI               |
| authorizedGrantType         | Array  | 등록된 클라이언트의 인증 방식                    |
| scope                       | Array  | 등록된 클라이언트의 스코프                       |
| owner                       | String | 등록된 클라이언트의 소유자                       |
| accessTokenValiditySeconds  | Number | 등록된 클라이언트의 Access Token 유효 기간 (초)  |
| refreshTokenValiditySeconds | Number | 등록된 클라이언트의 Refresh Token 유효 기간 (초) |

#### 에러
```
HTTP/1.1 400
Content-Type: application/json

{
    "errorCode": "exists_identifier",
    "description": "CLIENT-ID is exists"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------- |
| exists_identifier                    |    400    | 이미 사용중인 클라이언트 아이디임을 알리는 에러 코드 입니다.                    |
| invalid_request                      |    400    | 요청하신 클라이언트 정보중 허용 되지 않은 정보가 있음을 알리는 에러 코드 입니다. |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 등록된 클라이언트 검색
로그인한 계정에 등록된 클라이언트를 모두 반환 합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/clients
?page=0
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------------------------------- |
| page          | Optional  | Number | 검색할 페이지이며 0부터 시작 합니다. 입력되지 않을시 0으로 설정 됩니다. |

#### 응답
```
HTTP/1.1 OK
Content-Type: application/json

{
    "content": [
        {
            "clientId": "CLIENT-ID",
            "clientName": "CLIENT-NAME",
            "registeredRedirectUris": [
                "http://localhost:8080/callback",
                "http://localhost:8081/callback"
            ],
            "authorizedGrantTypes": [
                { "value": "refresh_token" },
                { "value": "client_credentials" },
                { "value": "authorization_code" }
            ],
            "scopes": [ "TEST-3", "TEST-1", "TEST-2" ],
            "owner": "email@email.com",
            "accessTokenValiditySeconds": 600,
            "refreshTokenValiditySeconds": 7200
        },
        {
            "clientId": "oauth-server",
            "clientName": "oauth-server",
            "registeredRedirectUris": [
                "http://localhost:9090/?test_parameter=test",
                "http://localhost:8080/"
            ],
            "authorizedGrantTypes": [
                { "value": "implicit" },
                { "value": "refresh_token" },
                { "value": "client_credentials" },
                { "value": "password" },
                { "value": "authorization_code" }
            ],
            "scopes": [ "TEST-3", "TEST-4","TEST-1",  "TEST-2" ],
            "owner": "email@email.com",
            "accessTokenValiditySeconds": 600,
            "refreshTokenValiditySeconds": 7200
        }
    ],
    "pageable": {
        "sort": { "sorted": false, "unsorted": true, "empty": true },
        "offset": 0,
        "pageNumber": 0,
        "pageSize": 10,
        "unpaged": false,
        "paged": true
    },
    "totalPages": 1,
    "totalElements": 2,
    "last": true,
    "size": 10,
    "number": 0,
    "sort": { "sorted": false, "unsorted": true, "empty": true },
    "numberOfElements": 2,
    "first": true,
    "empty": false
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| content                     | Array  | 검색된 클라이언트 리스트                         |
| clientId                    | String | 등록된 클라이언트의 아이디                       |
| clientName                  | String | 등록된 클라이언트의 이름                         |
| registeredRedirectURI       | Array  | 등록된 클라이언트의 리다이렉트 URI               |
| authorizedGrantType         | Array  | 등록된 클라이언트의 인증 방식                    |
| scope                       | Array  | 등록된 클라이언트의 스코프                       |
| owner                       | String | 등록된 클라이언트의 소유자                       |
| accessTokenValiditySeconds  | Number | 등록된 클라이언트의 Access Token 유효 기간 (초)  |
| refreshTokenValiditySeconds | Number | 등록된 클라이언트의 Refresh Token 유효 기간 (초) |
| totalPages                  | Number | 총 페이지 갯수                                  |
| size                        | Number | 한 페이지당 클라이언트 갯수                      |
| first                       | Boolean | 현재 페이지가 첫번쨰 페이지 인지 여부            |
| last                        | Boolean | 현재 페이지가 마지막 페이지 인지 여부            |

### 클라이언트 정보 변경
클라이언트의 정보를 변경 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/clients/{clientId=CLIENT-ID}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "clientName":   "MODIFY-CLIENT-NAME",
    "removeRedirectUris": ["http://localhost:8080/callback", "http://localhost:8081/callback"],
    "newRedirectUris": ["http://localhost:8082/callback", "http://localhost:8083/callback"],
    "removeScopes": ["TEST-1", "TEST-2"],
    "newScopes": [],
    "removeGrantTypes": ["authorization_code", "refresh_token", "client_credentials"],
    "newGrantTypes": ["password"]
}
```
|     파라미터명      | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | ------------------------------------------------------------------- |
| clientId           | Required  | String | 수정할 클라이언트의 아이디                                            |
| clientName         | Required  | String | 변경할 클라이언트 이름                                                |
| removeRedirectUris | Required  | Array  | 삭제할 리다이렉트 URI. 빈 배열일시 리다이렉트 URI를 삭제하지 않습니다.   |
| newRedirectUris    | Required  | Array  | 추가할 리다이렉트 URI. 빈 배열일시 리다이렉트 URI를 추가하지 않습니다.   |
| removeScopes       | Required  | Array  | 삭제할 스코프. 빈 배열일시 스코프를 삭제하지 않습니다.                   |
| newScopes          | Required  | Array  | 추가할 스코프. 빈 배열일시 스코프를 추가히지 않습니다.                   |
| removeGrantTypes   | Required  | Array  | 삭제할 인증 타입. 빈 배열일시 인증 타입을 삭제하지 않습니다.             |
| newGrantTypes      | Required  | Array  | 추가할 인증 타입. 빈 배열일시 인증 타입을 추가하지 않습니다.             |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "clientId": "CLIENT-ID",
    "clientName": "MODIFY-CLIENT-NAME",
    "registeredRedirectUris": [
        "http://localhost:8083/callback",
        "http://localhost:8082/callback"
    ],
    "authorizedGrantTypes": [
        { "value": "password" }
    ],
    "scopes": [ "TEST-3" ],
    "owner": "email@email.com",
    "accessTokenValiditySeconds": 600,
    "refreshTokenValiditySeconds": 7200
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| clientId                    | String | 수정된 클라이언트의 아이디                       |
| clientName                  | String | 수정된 클라이언트의 이름                         |
| registeredRedirectURI       | Array  | 수정된 클라이언트의 리다이렉트 URI               |
| authorizedGrantType         | Array  | 수정된 클라이언트의 인증 방식                    |
| scope                       | Array  | 수정된 클라이언트의 스코프                       |
| owner                       | String | 수정된 클라이언트의 소유자                       |
| accessTokenValiditySeconds  | Number | 수정된 클라이언트의 Access Token 유효 기간 (초)  |
| refreshTokenValiditySeconds | Number | 수정된 클라이언트의 Refresh Token 유효 기간 (초) |

#### 에러
```
HTTP/1.1 400
Content-Type: application/json

{
    "errorCode": "exists_identifier",
    "description": "CLIENT-ID is exists"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------- |
| invalid_request                      |    400    | 변경하려는 클라이언트 정보중 허용 되지 않은 정보가 있음을 알리는 에러 코드 입니다. |
| invalid_owner                        |    401    | 수정하려는 클라이언트가 다른 소유자의 클라이언트임을 알리는 에러 코드 입니다.    |
| not_found                            |    404    | 수정하려는 클라이언트를 찾을 수 없음을 알리는 에러 코드 입니다.                 |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 클라이언트 삭제
클라이언트를 삭제 합니다.

#### 요청
```
DELETE HTTP/1.1
http://localhost:8080/api/clients/{clientId=CLIENT-ID}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99
```
|     파라미터명      | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | ------------------------------------------------------------------- |
| clientId           | Required  | String | 삭제할 클라이언트의 아이디                                            |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "clientId": "CLIENT-ID",
    "clientName": "MODIFY-CLIENT-NAME",
    "registeredRedirectUris": [
        "http://localhost:8083/callback",
        "http://localhost:8082/callback"
    ],
    "authorizedGrantTypes": [
        { "value": "password" }
    ],
    "scopes": [ "TEST-3" ],
    "owner": "email@email.com",
    "accessTokenValiditySeconds": 600,
    "refreshTokenValiditySeconds": 7200
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| clientId                    | String | 삭제된 클라이언트의 아이디                       |
| clientName                  | String | 삭제된 클라이언트의 이름                         |
| registeredRedirectURI       | Array  | 삭제된 클라이언트의 리다이렉트 URI               |
| authorizedGrantType         | Array  | 삭제된 클라이언트의 인증 방식                    |
| scope                       | Array  | 삭제된 클라이언트의 스코프                       |
| owner                       | String | 삭제된 클라이언트의 소유자                       |
| accessTokenValiditySeconds  | Number | 삭제된 클라이언트의 Access Token 유효 기간 (초)  |
| refreshTokenValiditySeconds | Number | 삭제된 클라이언트의 Refresh Token 유효 기간 (초) |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "CLIENT-ID is not found"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------- |
| invalid_owner                        |    401    | 수정하려는 클라이언트가 다른 소유자의 클라이언트임을 알리는 에러 코드 입니다.    |
| not_found                            |    404    | 수정하려는 클라이언트를 찾을 수 없음을 알리는 에러 코드 입니다.                 |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 클라이언트 패스워드 변경
클라이언트의 패스워드를 변경 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/clients/{clientId=CLIENT-ID}/attributes/secret

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "existsSecret": "CLIENT-SECRET",
    "newSecret": "NEW-CLIENT-SECRET"
}
```
|     파라미터명      | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | ------------------------------------------------------------------- |
| clientId           | Required  | String | 수정할 클라이언트의 아이디                                            |
| existsSecret       | Required  | String | 수정할 클라이언트의 기존에 사용중이던 패스워드                         |
| newSecret          | Required  | String | 변경할 클라이언트의 패스워드                                          |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "clientId": "CLIENT-ID",
    "clientName": "MODIFY-CLIENT-NAME",
    "registeredRedirectUris": [
        "http://localhost:8083/callback",
        "http://localhost:8082/callback"
    ],
    "authorizedGrantTypes": [
        { "value": "password" }
    ],
    "scopes": [ "TEST-3" ],
    "owner": "email@email.com",
    "accessTokenValiditySeconds": 600,
    "refreshTokenValiditySeconds": 7200
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| clientId                    | String | 변경된 클라이언트의 아이디                       |
| clientName                  | String | 변경된 클라이언트의 이름                         |
| registeredRedirectURI       | Array  | 변경된 클라이언트의 리다이렉트 URI               |
| authorizedGrantType         | Array  | 변경된 클라이언트의 인증 방식                    |
| scope                       | Array  | 변경된 클라이언트의 스코프                       |
| owner                       | String | 변경된 클라이언트의 소유자                       |
| accessTokenValiditySeconds  | Number | 변경된 클라이언트의 Access Token 유효 기간 (초)  |
| refreshTokenValiditySeconds | Number | 변경된 클라이언트의 Refresh Token 유효 기간 (초) |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "CLIENT-ID is not found"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | -------------------------------------------------------------------------- |
| invalid_request                      |    400    | 변경하려는 클라이언트 정보중 유효하지 않은 정보가 있음을 알리는 에러 코드 입니다. |
| invalid_owner                        |    401    | 수정하려는 클라이언트가 다른 소유자의 클라이언트임을 알리는 에러 코드 입니다.    |
| not_found                            |    404    | 수정하려는 클라이언트를 찾을 수 없음을 알리는 에러 코드 입니다.                 |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 클라이언트 아이디 갯수 검색
저장소에 저장된 클라이언트 아이디의 갯수를 검색합니다. 주로 클라이언트의 아이디 중복 검사를 할 때 사용 합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/attributes/id
?clientId=CLIENT-ID
```
|     파라미터명      | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | ------------------------------------------------------------------- |
| clientId           | Required  | String | 검색할 클라이언트 아이디                                             |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "count": 1
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| count         | Number | 등록된 클라이언트 아이디의 갯수 |

## OAuth2 스코프 HTTP API
OAuth2 스코프의 추가와 삭제, 수정을 하는 HTTP API 입니다. 등록된 스코프를 검색하는 API를 제외하고 관리자로 로그인된 계정만
접근 할 수 있도록 설정 해야 합니다. 아래는 현재 구현된 스코프 HTTP API 리스트 입니다.

- [새 스코프 등록](#새-스코프-등록)
- [등록된 스코프 검색](#모든-스코프-검색)
- [스코프 정보 변경](#스코프-정보-변경)
- [스코프 삭제](#스코프-삭제)
- [저장된 스코프 갯수 검색](#스코프-아이디-갯수-검색)

### 새 스코프 등록
새 스코프를 등록 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/scopes

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "scopeId": "TEST-SCOPE-1",
    "description": "테스트용 스코프 1",
    "accessibleAuthority": ["TEST-ROLE-1", "TEST-ROLE-2"]
}
```
|     파라미터명      | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | ------------------------------------- |
| scopeId              | Required  | String | 추가할 스코프의 아이디               |
| description          | Required  | String | 추가할 스코프의 설명 텍스트          |
| accessibleAuthority  | Required  | String | 해당 스코프에 접근 가능한 유저 권한  |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "scopeId": "TEST-SCOPE-1",
    "description": "테스트용 스코프 1",
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| scopeId                     | String | 추가된 스코프의 아이디                           |
| description                 | String | 추가된 스코프의 설명 텍스트                      |

#### 에러
```
HTTP/1.1 400
Content-Type: application/json

{
    "errorCode": "exists_identifier",
    "description": "TEST-SCOPE-1 is exists"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | -------------------------------------------------------------------------- |
| invalid_request                      |    400    | 추가하려는 스코프 정보중 유효하지 않은 정보가 있음을 알리는 에러 코드 입니다.    |
| exists_identifier                    |    400    | 추가하려는 스코프의 아이디가 이미 사용중임을 알리는 에러 코드 입니다.            |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 모든 스코프 검색
계정된 로그인 권한으로 접근할 수 있는 모든 스코프를 검색하여 반환합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/scopes
```

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "scopes": [
        {
            "scopeId": "TEST",
            "description": "테스트 확인용 스코프"
        },
        {
            "scopeId": "TEST-1",
            "description": "테스트 확인용 스코프 1"
        },
        {
            "scopeId": "TEST-2",
            "description": "테스트 확인용 스코프 2"
        },
        {
            "scopeId": "TEST-3",
            "description": "테스트 확인용 스코프 3"
        },
        {
            "scopeId": "TEST-4",
            "description": "테스트 확인용 스코프 4"
        },
        {
            "scopeId": "TEST-5",
            "description": "테스트용 스코프 5"
        },
        {
            "scopeId": "TEST-SCOPE-1",
            "description": "테스트용 스코프 1"
        }
    ]
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| scopes                      | Array  | 검색된 스코프 리스트                             |
| scopeId                     | String | 검색된 스코프의 아이디                           |
| description                 | String | 검색된 스코프의 설명 텍스트                      |

### 스코프 정보 변경
스코프의 정보를 변경 합니다

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/scopes/{scopeId=TEST-SCOPE-1}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "description": "변경된 스코프 설명 텍스트",
    "removeAccessibleAuthority": ["TEST_ROLE_1"],
    "newAccessibleAuthority": ["TEST_ROLE_2"]
}
```
|     파라미터명             | 필수 여부 |  타입   |  설명  |
| :-----------------------: | :-------: | :----: | ------------------------------------- |
| scopeId                   | Required  | String | 수정할 스코프의 아이디               |
| description               | Required  | String | 변경할 스코프의 설명 텍스트          |
| removeAccessibleAuthority | Required  | Array  | 삭제할 스코프에 접근 가능한 유저 권한 |
| newAccessibleAuthority    | Required  | Array  | 추가할 스코프에 접근 가능한 유저 권한 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "scopeId": "TEST-SCOPE-1",
    "description": "변경된 스코프 설명 텍스트",
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| scopeId                     | String | 변경된 스코프의 아이디                           |
| description                 | String | 변경된 스코프의 설명 텍스트                      |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "TEST-SCOPE-1 is not found"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | -------------------------------------------------------------------------- |
| invalid_request                      |    400    | 변경하려는 스코프 정보중 유효하지 않은 정보가 있음을 알리는 에러 코드 입니다.    |
| not_found                            |    404    | 수정하려는 스코프를 찾을 수 없음을 알리는 에러 코드 입니다.                     |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 스코프 삭제
스코프를 삭제 합니다.

#### 요청
```
DELETE HTTP/1.1
http://localhost:8080/api/scopes/{scopeId=TEST-SCOPE-1}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99
```
|     파라미터명      | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | ------------------------------------------------------------------- |
| scopeId           | Required  | String | 삭제할 스코프의 아이디                                            |

#### 응답
```
HTTP/1.1 2000
Content-Type: application/json

{
    "scopeId": "TEST-SCOPE-1",
    "description": "스코프 설명 텍스트",
}
```
|          파라미터명          |  타입  |                       설명                     |
| :-------------------------: | :----: | ---------------------------------------------- |
| scopeId                     | String | 삭제된 스코프의 아이디                           |
| description                 | String | 삭제된 스코프의 설명 텍스트                      |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "TEST-SCOPE-1 is not found"
}
```
|              에러 코드               | 상태 코드 |                                   설명                                       |
| :----------------------------------: | :---------: | -------------------------------------------------------------------------- |
| not_found                            |    404    | 삭제하려는 스코프를 찾을 수 없음을 알리는 에러 코드 입니다.                     |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                 |

### 스코프 아이디 갯수 검색
저장소에 저장된 스코프 아이디의 갯수를 검색합니다. 주로 스코프 아이디의 중복 검사를 할 때 사용 합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/scopes/attributes/scopeId
?scopeId=TEST-SCOPE-1
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------ |
| scopeId       | Required  | String | 검색할 스코프 아이디 |

### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "count": 1
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| count         | Number | 등록된 스포크 아이디 갯수 |