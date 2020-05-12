## 보호 자원 HTTP API
보호 자원 (엔드포인트)에 대한 추가와 수정, 조회를 하는 HTTP API 입니다. 관리자 권한을 가진 계정으로 로그인 했을시만 접근 할 수 있도록 설정 해야 합니다.
아래는 현재 구현된 보호 자원 HTTP API 리스트 입니다.

[새 보호 자원 등록](#새-보호-자원-등록)  
[모든 보호 자원 검색](#모든-보호-자원-검색)  
[보호 자원 수정](#보호-자원-수정)
[보호 자원 삭제](#보호-자원-삭제)  
[보호 자원 아이디 갯수 검색](#보호-자원-아이디-갯수-검색)


### 새 보호 자원 등록
새 보호 자원을 등록 합니다.

#### 요청
```
POST HTTP/1.1
http://localhost:8080/api/secured-resources

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "resourceId": "RESOURCE-1",
    "resource": "/user/**",
    "method": "post",
    "authorities": ["AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3"]
}
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------------------------------------ |
| resourceId    | Required  | String | 추가할 보호 자원 아이디                                                    |
| resource      | Required  | String | 보호 자원 형식으로 URI 패턴으로 입력합니다.                                 |
| method        | Required  | String | 보호 자원의 HTTP 메소드로 모든 메소드를 보호 하고 싶을땐 'ALL' 을 입력합니다. |
| authorities   | Optional  | Array | 보호 자원에 접근 가능한 스코프 아이디                                            |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
	"resourceId": "RESOURCE-1",
	"resource": "/user/**",
	"method": "POST",
    "authorities": ["AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3"]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ----------------------- |
| resourceId    | String | 추가된 보호 자원 아이디  |
| resource      | String | 추가된 보호 자원 형식    |
| method        | String | 추가된 보호 자원의 메소드 |
| authorities   | Array | 보호 자원에 접근 가능한 스코프 아이디 |

#### 에러
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| invalid_request                       |    400    | 요청하신 정보중 허용되지 않는 정보가 있습니다.                               |
| exists_identifier                    |    400    | 요청하신 자원 아이디는 이미 사용중 입니다.                                   |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 모든 보호 자원 검색
저장소에 저장된 모든 보호 자원을 검색 합니다.

#### 요청
```
GET HTTP/1.1

http://localhost:8080/api/secured-resources
```

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
    "resources": [
        {
            "resourceId": "RESOURCE-1",
            "resource": "/user/**/1",
            "method": "ALL",
            "authorities": ["AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3"]
        },
        {
            "resourceId": "RESOURCE-2",
            "resource": "/user/**/2",
            "method": "ALL",
            "authorities": ["AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3"]
        },
        {
            "resourceId": "RESOURCE-3",
            "resource": "/user/**/3",
            "method": "ALL",
            "authorities": ["AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3"]
        }
    ]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ----------------------- |
| resources    | Array | 검색된 보호 자원  |
| resourceId    | String | 보호 자원 아이디  |
| resource      | String | 보호 자원 형식    |
| method        | String | 보호 자원의 메소드 |
| authorities   | Array | 보호 자원에 접근 가능한 스코프 아이디 |

### 보호 자원 수정
보호 자원의 정보를 변경 합니다.

#### 요청
```
PUT HTTP/1.1
http://localhost:8080/api/secured-resources/{resourceId=RESOURCE-1}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99

{
    "resource": "/user/**",
    "method": "post",
    "newAuthorities": ["AUTHORITY-4", "AUTHORITY-5"],
    "removeAuthorities": ["AUTHORITY-1", "AUTHORITY-2"]
}
```
|  파라미터명     | 필수 여부 |  타입   |  설명  |
| :-------------:  | :-------: | :----: | ------------------------------------------------------------------------ |
| resourceId      | Required  | String | 수정할 보호 자원 아이디                                                    |
| resource        | Required  | String | 수정할 보호 자원 형식으로 URI 패턴으로 입력합니다.                                 |
| method          | Required  | String | 수정할 보호 자원의 HTTP 메소드로 모든 메소드를 보호 하고 싶을땐 'ALL' 을 입력합니다. |
| newAuthorities  | Optional  | Array | 추가할 보호 자원에 접근 가능한 스코프 아이디                                            |
| removeAuthorities | Optional  | Array | 제거할 보호 자원에 접근 가능한 스코프 아이디                                            |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
	"resourceId": "RESOURCE-1",
	"resource": "/user/**",
	"method": "POST",
    "authorities": ["AUTHORITY-3", "AUTHORITY-4", "AUTHORITY-5"]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ----------------------- |
| resourceId    | String | 수정된 보호 자원 아이디  |
| resource      | String | 수정된 보호 자원 형식    |
| method        | String | 수정된 보호 자원의 메소드 |
| authorities   | Array | 보호 자원에 접근 가능한 스코프 아이디 |

#### 에러
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| invalid_request                       |    400    | 요청하신 정보중 허용되지 않는 정보가 있습니다.                               |
| not_found                             |    404    | 수정 하려는 보호 자원을 찾을 수 없습니다.                               |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |

### 보호 자원 삭제
보호 자원을 저장소에서 삭제합니다. 삭제된 보호 자원은 로그인을 하지 않아도 접근 할 수 있게 됩니다.

#### 요청
```
DELETE HTTP/1.1
http://localhost:8080/api/secured-resources/{resourceId=RESOURCE-1}

X-CSRF-TOKEN: 02d40025-cb71-4fef-b49b-93849a668a99
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | ------------------------------------------------------------------------ |
| resourceId    | Required  | String | 삭제할 보호 자원 아이디                                                    |

#### 응답
```
HTTP/1.1 200
Content-Type: application/json

{
	"resourceId": "RESOURCE-1",
	"resource": "/user/**",
	"method": "POST",
    "authorities": ["AUTHORITY-1", "AUTHORITY-2", "AUTHORITY-3"]
}
```
|  파라미터명    |  타입   |  설명  |
| :-----------: | :----: | ----------------------- |
| resourceId    | String | 삭제된 보호 자원 아이디  |
| resource      | String | 삭제된 보호 자원 형식    |
| method        | String | 삭제된 보호 자원의 메소드 |
| authorities   | Array | 보호 자원에 접근 가능한 스코프 아이디 |

#### 에러
|              에러 코드                | 상태 코드 |                                   설명                                      |
| :----------------------------------: | :---------: | ------------------------------------------------------------------------ |
| not_found                             |    404    | 삭제 하려는 보호 자원을 찾을 수 없습니다.                               |
| server_error                         |    500    | 서버에서 알 수 없는 에러가 발생 했음을 알리는 에러 코드 입니다.                |


### 보호 자원 아이디 갯수 검색
저장소에 저장된 보호 자원의 아이디 갯수를 검색 합니다. 보통 아이디 중복 여부를 확인 할 때 사용 합니다.


#### 요청
```
GET HTTP/1.1
http://localhost:8080/api/secured-resources/attributes/resource-id
?resourceId=xxxxxxxxxx
```
|  파라미터명    | 필수 여부 |  타입   |  설명  |
| :-----------: | :-------: | :----: | -------------- |
| resourceId    | Required  | String | 검색할 보호 자원 아이디 |

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
| count         | Number | 등록된 보호 자원 아이디의 갯수 |