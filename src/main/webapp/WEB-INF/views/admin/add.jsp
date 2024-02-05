<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="../head.jsp"></jsp:include>
<script>
document.addEventListener('DOMContentLoaded', (event) => {		
	//엔테키 누를 시 submit 함수 실행
	document.getElementById('addAdminForm').addEventListener('keydown', function(event) {
        var keyCode = event.keyCode;
        if (keyCode == 13) {
            event.preventDefault(); // 기본 이벤트를 취소합니다.
            submit();
        }
    });
});
//벨리데이션(검증)하는 코드들
function submit() {
	const form = document.addAdminForm;
	if(form.adminId.value != form.id_confirm.value) {
		alert('아이디 중복확인을 하세요');
		return;
	}
	else if(form.adminId.value == "") {
		alert('아이디를 입력 해 주세요');
		form.adminId.focus();
		return;
	}
	else if(form.adminPw.value == "") {
		alert('비밀번호를 입력 해 주세요');
		form.adminPw.focus();
		return;
	}
	else if(form.adminPw_confirm.value == "") {
		alert('비밀번호를 입력 해 주세요');
		form.adminPw_confirm.focus();
		return;
	}
	else if(form.adminPw.value != form.adminPw_confirm.value) {
		alert('비밀번호가 일치하지 않습니다');
		form.adminPw_confirm.value = "";
		form.adminPw_confirm.focus();
		return;
	}
	else if(form.adminName.value == "") {
		alert('이름을 입력 해 주세요');
		form.adminName.focus();
		return;
	}
	form.submit();
}
//1 == '1' => value(값)이 같으면 true, |  1 === '1' => type과 value 가 같아야 하므로 false
// confirmId 에서 사용한 코드들 = 에이젝, 즉 에이젝을 사용함
function confirmId(){
	// 에이젝을 사용하기 위한 객체생성
	const form = document.addAdminForm;
	
	const xhr = new XMLHttpRequest();
	
	// 비동기방식(true),에이젝의 제대로된 성능을 내려면 비동기 방식 채용
	xhr.open("GET", "confirmId?adminId=" + form.adminId.value, true);  
	
	xhr.onreadystatechange = function() {
		// DONE(처리가 됨)인 상태가 된다면..
		if(xhr.readyState == XMLHttpRequest.DONE) {
							
			// AJAX 요청이 정상적으로 처리되었는지 아닌지만을 검사하기 위해 응답 코드가 200 인지 확인
			if(xhr.status == 200) {
				if(xhr.responseText == 'OK') { 
					if(form.adminId.value != "")
					{
						alert("사용할수 있는 아이디 입니다");
						form.id_confirm.value = form.adminId.value;
					}
					else if(form.adminId.value == "")
					{
						alert('아이디를 입력 해 주세요');
						form.adminId.focus();
					}
				} else {
					alert('다른 관리자가 이미 사용하고 있는 아이디 입니다');
				}
			}
		}	
	};
	
	xhr.send();
	
}
</script>
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<div class="left-wrap">
	<h4 class="content-h4" style="line-height: 28px; color: #333;">관리자 메뉴</h4>
	<ul class="admin-list-nav">	
		<c:if test="${sessionScope.admin.adminId == 'admin'}">
			<li><a href="/admin/list" class="on">관리자관리</a></li>
		</c:if>
	    <li><a href="/user/list">회원관리</a></li>
		<li><a href="/orders/listAdmin">주문관리</a></li>
		<li><a href="/board/listAdmin">문의관리</a></li>
		<li><a href="/keycap/add">상품등록</a></li>
		<li><a href="/keycap/list?sort=null">상품관리</a></li>
	</ul>
</div>
	<!-- <button>을 쓰면 내 의도와 상관없이 submit 되어버림,고로 form태그 바깥으로 놔야함 -->
	<div class="sign-wrap">
		<!-- Title  -->
		<div class="login-text">
			<h2>관리자 등록</h2>
		</div>
		<div class="signup-text">
			<i class="fas fa-check"></i>
			<span>항목은 <span style="color: #333;">필수 입력</span> 항목입니다.</span>
		</div>
		<!-- Form 입력 -->
		<div class="signup-form" style="height: auto;">
			<form id="addAdminForm" name="addAdminForm" method="post">
			<input name="id_confirm" type="hidden" value="" >
			<div class="login-entry">
				<fieldset>
				<div class="signup-list">
				<ul class="text">
					<li class="th"><p>아이디</p><i class="fas fa-check"></i></li>
					<li class="td">
					<!-- 특수문자, 띄어쓰기,한국어 등 사용불가 replace(/[^a-zA-Z0-9]/g, '') -->
						<input name="adminId" type="text" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');">
						<button type="button" onclick="location.href='javascript:confirmId()';" style="cursor: pointer;">중복검사</button>
					</li>
				</ul>
				<ul class="text">	
					<li class="th"><p>비밀번호</p><i class="fas fa-check"></i></li>
					<li class="td"><input name="adminPw" type="password" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');"></li>
				</ul>
				<ul class="text">
					<li class="th"><p>비밀번호 재확인</p><i class="fas fa-check"></i></li>
					<li class="td"><input name="adminPw_confirm" type="password" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');"></li>
				</ul>
				<ul class="text">
					<li class="th"><p>이름</p><i class="fas fa-check"></i></li>
					<!-- 입력 값이 변경될 때마다 oninput 이벤트 핸들러가 실행되어 한글 입력 중인 문자까지 제거되기 때문에 발생하기에.. oniput을 않씀 -->
					<li class="td"><input name="adminName" type="text"></li>
				</ul>
				<ul class="text">
					<li class="th"><p>관리자 여부</p><i class="fas fa-check"></i></li>
					<!-- 입력 값이 변경될 때마다 oninput 이벤트 핸들러가 실행되어 한글 입력 중인 문자까지 제거되기 때문에 발생하기에.. oniput을 않씀 -->
					<li class="td">
						<div style="display: flex; justify-content: left;">
							<input name="adminState" type="radio" value="1" checked="checked" style="width: 15px; height: auto;">
							<div style="margin: 0 5px;">승인</div>
							<input name="adminState" type="radio" value="0" style="width: 15px; height: auto; margin-left: 10px;">
							<div style="margin: 0 5px;">대기</div>
						</div>
					</li>
				</ul>		
				</div>
				</fieldset>
			</div>
			</form>
			<!-- form태그 바깥에 버튼을 두면 엔터키가 안먹힘 -->
			<div id="signup02">
				<button onclick="submit()" class="signup-btn">입력 완료</button>
			</div>
		</div>
	</div>
<!-- contents-layout  -->
<div class="clear"></div>
<div id="overflow-hidden-admin"></div>
	<div class="footer">
		<ul class="footer_contents">
			<li class="footer-a">[34503] 대전광역시 동구 우암로 352-21  [대표전화] 042-670-0600  
				COPYRIGHT 2010 BY KOREA POLYTECHNICS. ALL RIGHTS RESERVED.</li>
				<li class="footer-b">CUSTOMER CENTER
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