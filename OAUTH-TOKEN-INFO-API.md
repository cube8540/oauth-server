# 토큰 정보 API
권한 서버에게 토큰의 정보를 요청하여 토큰의 유효 여부 혹은 토큰을 부여 받은 유저의 정보를 검색하는 API 입니다.

- [토큰 정보 검색](#토큰-정보-검색)
- [유저 정보 검색](#유저-정보-검색)

## 에러
- [에러 코드](#에러-코드)

### 토큰 정보 검색
토큰의 정보를 검색합니다. 요청을 한 클라이언트는 인증을 받아야 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/oauth/token_info
?token=xxxxxxxxxxxxxxx
&client_id=<your-client-id>
&client_secret=<your-client-secret>
```
|  파라미터명    |  필수 여부     |  타입   |  설명  |
| :-----------:   | :--------------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| token           | Required       | String | 정보를 검색할 토큰값                                                                                                |
| client_id       | Optional       | URI    | 토큰을 부여해준 클라이언트의 아이디                                                                                 |
| client_secret   | Optional       | String | 토큰을 부여해준 클라이언트의 아이디                                                                                 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "scope": "TEST-SCOPE-2 TEST-SCOPE-1",
    "active": true,
    "exp": 1583501730,
    "client_id": "client-2",
    "username": "email@email.com"
}
```
|  파라미터명   |  타입   |  설명  |
| :-----------:  | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| scope          | String | 토큰에 부여된 스코프                                                                                              |
| active         | Boolean| 토큰의 유효성 여부 true 일시 유효한 상태이며 false 이면 유효하지 않은 상태 입니다.                                   |
| exp            | Number | 토큰의 만료일 까지 남은 시간 (초)                                                                                 |
| client_id      | String | 토큰을 부여해준 클라이언트의 아이디                                                                                |
| username       | String | 토큰 소유자의 아이디                                                                                              |

### 유저 정보 검색
토큰을 부여 받은 유저의 정보를 검색 합니다. 요청을 한 클라이언트는 인증을 받아야 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/oauth/user_info
?token=xxxxxxxxxxxxxxx
&client_id=<your-client-id>
&client_secret=<your-client-secret>
```
|  파라미터명    |  필수 여부     |  타입   |  설명  |
| :-----------:   | :--------------: | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| token           | Required       | String | 정보를 검색할 토큰값                                                                                                |
| client_id       | Optional       | URI    | 토큰을 부여해준 클라이언트의 아이디                                                                                 |
| client_secret   | Optional       | String | 토큰을 부여해준 클라이언트의 아이디                                                                                 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "username": "email@email.com",
    "authorities": [
        {
            "authority": "ROLE_USER"
        }
    ],
    "accountNonExpired": true,
    "accountNonLocked": true,
    "credentialsNonExpired": true,
    "enabled": true
}
```
|  파라미터명             |  타입   |  설명  |
| :-------------------:  | :-----:  | -------------------------------------------------------------------------------------------------------------- |
| username               | String | 유저 아이디                                                                                                       |
| authorities            | Array  | 유저에 할당된 권한                                                                                                |
| accountNonExpired      | Boolean | 계정의 만료 여부로 true 일시 만료 되지 않았음을 나타내며 false 일시 만료 되었음을 나타냅니다.                        |
| accountNonLocked       | Boolean | 계정의 잠금 여부로 true 일시 잠기지 않았음을 나타내며 false 일시 잠겼음을 나타냅니다.                               |
| credentialsNonExpired  | Boolean | 패스워드의 만료 여부로 true 일시 만료되지 않았음을 나타내며 false 일시 만료 되었음을 나타냅니다.                     |
| enabled                | Boolean | 계정의 활성화 여부로 true 일시 활성화 되었음을 false 일시 활성화 되지 않았음을 나타냅니다.                           |

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