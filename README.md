# (!개편전 프로젝트!)휘캡(Hwicap) 
## 휘캡(Hwicap) 프로젝트는 키캡 온라인 쇼핑몰 콘셉트의 웹 사이트 입니다.
- 기술 스택 학습 목적의 프로젝트로 Spring, OAuth 소셜로그인 관련 기술 습득에 초점을 맞추어 제작하였습니다.

### 적용 기술
- Java 8, Spring, Spring Framework, Spring Security를 이용한 RESTful API를 구현한 웹 사이트 구현
- AJAX 자바스크립트를 이용해서 비동기식으로 서버와 통신하는 동안 다른 작업 가능
- Spring MVC 패턴

### 주요 기능
- OAuth 로그인을 이용한 간편 소셜 로그인
- 로그인 하면 Spring Security의 기능 CSRF 토큰을 발급하여 세션에 저장하고 인터셉터(Interceptor)로 해당 회원 정보가 세션에 저장
- 간편한 결제 및 장바구니 기능으로 회원은 빠르게 상품을 구매
- 검색 기능으로 상품 과 주문내역을 쉽게 찾음
- AJAX을 이용한 비동기적 회원가입 기능 및 장바구니, 찜하기 기능
- 파일업로드 기능 및 ckEditor5 를 이용한 이미지 업로드 및 게시글 작성(상품등록, 구매후기, 상품문의 등) 

### 기대효과 및 활용 분야
- 소셜 로그인을 통한 간편 로그인
- 인터셉터(Interceptor)로 사용자와 관리자 구분
- CSRF 토큰과 세션에 저장된 토큰이 일치하는지 검사하여 CSRF 공격을 방어
- 관리자와 회원의 손쉬운 소통
- 회원이 원하는 상품 빠른 구매 가능
