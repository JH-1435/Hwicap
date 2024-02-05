<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="head.jsp"></jsp:include>	
<script>
document.addEventListener('DOMContentLoaded', (event) => {
	//엔테키 누를 시 submit 함수 실행
	document.getElementById('loginFormAdmin').addEventListener('keydown', function(event) {
        var keyCode = event.keyCode;
        if (keyCode == 13) {
            event.preventDefault(); // 기본 이벤트를 취소합니다.
            submit();
        }
    });
});

//벨리데이션(검증)하는 코드들
function submit() {
	const form = document.loginFormAdmin;
			
	if(form.adminId.value == "") {
		alert("아이디를 입력 해 주세요");
		form.adminId.focus();
		return;
	}
	else if(form.adminPw.value == "") {
		alert("비밀번호를 입력 해 주세요");
		form.adminPw.focus();
		return;
	}
			
	form.submit();
}
</script>

</head>
<body>
<div class="wrap">
<header id="header-wrap">
<div class="status-bar">
	<div class="nav" style="padding-top: 46.67px;">
        <div class="logo-container">
            <a href="/"><img src="img/logo-main.png" class="logo"/></a>
        </div>
        <div class="nav-list-container">
            <ul class="nav-list">
                <li><a href="/keycap/list?sort=null">키캡</a></li>
                <li><a href="/keycap/list?sort=null">NEW</a></li>
                <li><a href="/keycap/list?sort=best">BEST</a></li>
                <c:if test="${sessionScope.user == null}">
                	<li><a href="/login">1대1 문의</a></li>
                </c:if>
                <c:if test="${sessionScope.user != null}">
                	<li><a href="/board/${sessionScope.user.userId}/addCs">1대1 문의</a></li>
                </c:if>
            </ul>
        </div>
    </div>
</div>
</header>
<!-- <button>을 쓰면 내 의도와 상관없이 submit 되어버림,고로 form태그 바깥으로 놔야함 -->
 <div class="login-wrap">
	<!-- Title  -->
		<div class="login-text">
			<h2>로그인(관리자)</h2>
		</div>
		<!-- Form 입력 -->
	<div class="login-form">
<div class="login-entry">
<form method="post" name="loginFormAdmin" id="loginFormAdmin">
		<fieldset>
	<div class="login-list">
		<ul class="text" style="padding-inline-start: 0;">
		 	<li>
		 	<!-- 특수문자, 띄어쓰기, 한국어 등  사용불가 replace(/[^a-zA-Z0-9]/g, '') -->
				<input name="adminId" type="text" placeholder="아이디" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');" >
			</li>
			<li>
				<input name="adminPw" type="password" placeholder="비밀번호" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');">
			</li>
		</ul>
	</div>
		</fieldset>
</form>
</div>
	<!-- 폼태그 안에 있는 버튼은 따로 지정을 안해도 무조건 submit이 된다, form태그 바깥에 버튼을 두면 엔터키가 안먹힘 -->
	<div id="login">
		<button onclick="submit()" class="signup-btn">로그인</button>
	</div>
	</div>
</div>
	<div class="footer">
			<ul class="footer_contents">
				<li class="footer-a">
					[34503] 대전광역시 동구 우암로 352-21  [대표전화] 042-670-0600  
					COPYRIGHT 2010 BY KOREA POLYTECHNICS. ALL RIGHTS RESERVED.
				</li>
				<li class="footer-b">
					CUSTOMER CENTER
					<em style="color: #333; font-size: x-large;">042-637-0000</em>
					MON-FRI : 10 : 00 ~ 18 : 00
					LUNCH   : 12 : 00 ~ 13 : 00  /  SAT, SUN, HOLIDAY OFF
				</li>
			<li class="footer-c"><img src="/resources/img/logo-footer.png"></li>
		</ul>
	</div>
</div>
</body>
</html>