## OAuth2 토큰 HTTP API
현재 로그인된 계정의 OAuth 토큰을 검색하거나 삭제할 수 있습니다.

[OAuth2 토큰 검색](#OAuth-토큰-검색)  
[OAuth2 토큰 삭제](#OAuth-토큰-삭제)

### OAuth2 토큰 검색
현재 로그인된 계정의 OAuth 토큰을 검색합니다.

#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/tokens
```

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "tokens": [
        {
            "tokenValue": "853f092168be4a9d805d8cab9f655bd6",
            "client": {
                "clientId": "CLIENT-ID",
                "clientName": "CLIENT-NAME"
            },
            "username": "email@email.com",
            "issuedAt": "2020-03-18T19:52:33.351958",
            "expiresIn": 563,
            "additionalInformation": {}
        }
    ]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| tokens         | Array | 로그인된 계정의 인증 토큰 |
| tokenValue  | String | 인증 토큰 |
| client  | Object | 인증 토큰의 클라이언트 정보 |
| clientId  | String | 인증 토큰의 클라이언트 아이디 |
| clientName  | String | 인증 토큰의 클라이언트명 |
| username  | String | 인증 토큰의 소유자 |
| issuedAt  | Datetime | 인증 토큰의 발행일시 |
| expiresIn  | Number | 인증 토큰의 만료 까지 남은 시간 (초) |
| additionalInformation  | Object | 인증 토큰의 추가 정보 |

#### 에러
```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
    "errorCode": "access_denied",
    "description": "access denied"
}
```
|        에러 코드             | 상태 코드 |                                   설명                                      |
| :--------------------------: | :---------: | ------------------------------------------------------------------------ |
| access_denied             |    403    | 로그인이 되어 있지 않습니다.            |
| server_error                 |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### OAuth2 토큰 삭제
현재 로그인된 계정의 OAuth 토큰을 삭제 합니다.

#### 요청
```
DELETE HTTP/1.1
http://localhost:8080/api/tokens/{token=853f092168be4a9d805d8cab9f655bd6}

X-CSRF-TOKEN: 03eacf13-6f4a-4ea5-8d63-ae2fb0b39f06
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------ |
| token         | Required  | String | 삭제할 인증 토큰 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "access_token": "853f092168be4a9d805d8cab9f655bd6",
    "token_type": "Bearer",
    "expires_in": 599,
    "scope": "TEST-SCOPE-3 TEST-SCOPE-2 TEST-SCOPE-1",
    "refresh_token": "e20c68f011dd4b3ba34dd4147428d80e"
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ------------------- |
| access_token  | String | 삭제된 인증 토큰 |
| token_type  | String | 삭제된 인증 토큰의 타입 |
| expires_in  | Number | 삭제된 인증 토큰의 만료 까지 남은 시간 (초) |
| scope  | Array | 삭제된 인증 토큰에 부여 되었던 스코프 |
| refresh_token  | String | 삭제된 인증 토큰의 리플래시 토큰 |

#### 에러
```
HTTP/1.1 404
Content-Type: application/json

{
    "errorCode": "not_found",
    "description": "853f092168be4a9d805d8cab9f655bd6 not found"
}
```
|        에러 코드             | 상태 코드 |                                   설명                                      |
| :--------------------------: | :---------: | ------------------------------------------------------------------------ |
| access_denied             |    403    | 로그인이 되어 있지 않습니다.            |
| not_found                    |    404    | 요청하신 인증 토큰을 저장소에서 찾을 수 없습니다. |
| server_error                 |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |