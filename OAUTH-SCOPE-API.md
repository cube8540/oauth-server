## OAuth2 스코프 HTTP API
OAuth2 스코프의 추가와 삭제, 수정을 하는 HTTP API 입니다. 등록된 스코프를 검색하는 API를 제외하고 관리자로 로그인된 계정만
접근 할 수 있도록 설정 해야 합니다. 아래는 현재 구현된 스코프 HTTP API 리스트 입니다.

[새 스코프 등록](#새-스코프-등록)  
[등록된 스코프 검색](#모든-스코프-검색)  
[스코프 정보 변경](#스코프-정보-변경)  
[스코프 삭제](#스코프-삭제)  
[저장된 스코프 갯수 검색](#스코프-아이디-갯수-검색)

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
?scopeId=xxxxxxxxxxxxxxx
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