## 권한 HTTP API
새 권한을 추가하거나 삭제, 수정하는 HTTP API 입니다. 관리자 권한을 가진 계정으로 로그인 했을시만 접근 할 수 있도록 설정 해야 합니다.
아래는 현재 구현된 권한 HTTP API 리스트 입니다.

[새 권한 등록](#새-권한-등록)  
[모든 권한 검색](#저장된-모든-권한-검색)  
[권한 정보 변경](#권한-정보-변경)  
[권한 삭제](#권한-삭제)  
[저장된 권한 코드 갯수 검색](#권한-코드-갯수-검색)  

### 새 권한 등록
저장소에 새 권한을 등록 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/authorities

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "code": "TEST-ROLE",
    "description": "테스트 권한",
    "basic": true,
    "accessibleResources": ["RESOURCE-1", "RESOURCE-2", "RESOURCE-3"]
}
```
|  파라미터명        | 필수 여부 |  타입   |  설명  |
| :----------------: | :-------: | :----: | -------------------------------------------------- |
| code                | Required  | String | 추가할 권한 코드                                     |
| description         | Required  | String | 권한의 설명 텍스트                                   |
| basic               | Required  | Boolean | 기본 권한 여부로 true 일시 기본 권한으로 설정 됩니다. |
| accessibleResources | Optional  | Array | 권한이 접근 가능한 자원의 아이디 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "code": "TEST-ROLE",
    "description": "테스트 권한",
    "basic": true,
    "accessibleResources": ["RESOURCE-1", "RESOURCE-2", "RESOURCE-3"]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| code         | String | 추가된 권한 코드        |
| description  | String |추가된 권한의 설명 텍스트 |
| basic  | Boolean |추가된 권한의 기본 권한 여부 |
| accessibleResources | Array | 권한이 접근 가능한 자원의 아이디 |

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

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "authorities": [
        {
            "code": "ROLE_USER",
            "description": "테스트용 기본 권한",
            "basic": true,
            "accessibleResources": ["RESOURCE-1", "RESOURCE-2", "RESOURCE-3"]
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
| accessibleResources | Array | 권한이 접근 가능한 자원의 아이디 |

### 권한 정보 변경
권한의 정보를 변경 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/authorities/{code=TEST-ROLE}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "description": "변경된 설명 텍스트",
    "basic": true,
    "newAccessibleResources": ["RESOURCE-4", "RESOURCE-5"],
    "removeAccessibleResources": ["RESOURCE-1", "RESOURCE-2"]
}
```
|  파라미터명                | 필수 여부 |  타입   |  설명  |
| :-----------------------: | :-------: | :----: | -------------------------------------------------- |
| code                      | Required  | String | 변경할 권한 코드                                     |
| description               | Required  | String | 권한의 설명 텍스트                                   |
| basic                     | Required  | Boolean | 기본 권한 여부로 true 일시 기본 권한으로 설정 됩니다. |
| newAccessibleResources    | Optional  | Array | 권한에 추가할 접근 가능 자원 아이디 |
| removeAccessibleResources | Optional  | Array | 권한에서 제거할 접근 가능 자원 아이디 |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "code": "TEST-ROLE",
    "description": "변경된 설명 텍스트",
    "basic": true,
    "accessibleResources": ["RESOURCE-2", "RESOURCE-3", "RESOURCE-4", "RESOURCE-5"]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| code         | String | 변경된 권한 코드        |
| description  | String | 변경된 권한의 설명 텍스트 |
| basic  | Boolean | 변경된 권한의 기본 권한 여부 |
| accessibleResources | Array | 권한이 접근 가능한 자원의 아이디 |

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
    "basic": true,
    "accessibleResources": ["RESOURCE-2", "RESOURCE-3", "RESOURCE-4", "RESOURCE-5"]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | --------------------- |
| code         | String | 삭제된 권한 코드        |
| description  | String | 삭제된 권한의 설명 텍스트 |
| basic  | Boolean | 삭제된 권한의 기본 권한 여부 |
| accessibleResources | Array | 권한이 접근 가능한 자원의 아이디 |

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