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
?clientId=xxxxxxxxxxxxxxx
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