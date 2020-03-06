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
?email=xxxxxxxxxxxxxxx
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
?email=xxxxxxxxxxxxxxx

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