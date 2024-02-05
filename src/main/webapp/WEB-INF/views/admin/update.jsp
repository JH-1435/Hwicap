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
	document.getElementById('updateAdminForm').addEventListener('keydown', function(event) {
        var keyCode = event.keyCode;
        if (keyCode == 13) {
            event.preventDefault(); // 기본 이벤트를 취소합니다.
            submit();
        }
    });
});
//벨리데이션(검증)하는 코드들
function submit() {
	const form = document.updateAdminForm;
	if(form.adminPw.value == "") {
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
			<h2>관리자 수정</h2>
		</div>
		<div class="signup-text">
			<i class="fas fa-check"></i>
			<span>항목은 <span style="color: #333;">필수 입력</span> 항목입니다.</span>
		</div>
		<!-- Form 입력 -->
		<div class="signup-form" style="height: auto;">
			<form id="updateAdminForm" name="updateAdminForm" method="post">
			<div class="login-entry">
				<fieldset>
				<div class="signup-list">
				<ul class="text">
					<li class="th"><p>아이디</p></li>
					<li class="td">
						<p>${item.adminId}</p>
						<input name="adminId" type="hidden">
					</li>
					<li style="width: 1px; border-left: none;"></li>
				</ul>
				<ul class="text">	
					<li class="th"><p>비밀번호</p><i class="fas fa-check"></i></li>
					<li class="td"><input name="adminPw" type="password" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');"></li>
					<li style="width: 100%; border-left: none;"></li>
				</ul>
				<ul class="text">
					<li class="th"><p>비밀번호 재확인</p><i class="fas fa-check"></i></li>
					<li class="td"><input name="adminPw_confirm" type="password" oninput="this.value = this.value.replace(/[^a-zA-Z0-9]/g, '');"></li>
					<li style="width: 100%; border-left: none;"></li>
				</ul>
				<ul class="text">
					<li class="th"><p>이름</p><i class="fas fa-check"></i></li>
					<!-- 입력 값이 변경될 때마다 oninput 이벤트 핸들러가 실행되어 한글 입력 중인 문자까지 제거되기 때문에 발생하기에.. oniput을 않씀 -->
					<li class="td"><input name="adminName" type="text"></li>
					<li style="width: 100%; border-left: none;"></li>
				</ul>
				<ul class="text">
					<li class="th"><p>관리자 여부</p><i class="fas fa-check"></i></li>
					<!-- 입력 값이 변경될 때마다 oninput 이벤트 핸들러가 실행되어 한글 입력 중인 문자까지 제거되기 때문에 발생하기에.. oniput을 않씀 -->
					<li class="td">
						<div style="display: flex; justify-content: left;">
						<c:if test="${item.adminState == 1}">
							<input name="adminState" type="radio" value="1" checked="checked" style="width: 15px; height: auto;">
							<div style="margin: 0 5px;">승인</div>
							<input name="adminState" type="radio" value="0" style="width: 15px; height: auto; margin-left: 10px;">
							<div style="margin: 0 5px;">대기</div>
						</c:if>
						<c:if test="${item.adminState != 1}">
							<input name="adminState" type="radio" value="1" style="width: 15px; height: auto;">
							<div style="margin: 0 5px;">승인</div>
							<input name="adminState" type="radio" value="0" checked="checked" style="width: 15px; height: auto; margin-left: 10px;">
							<div style="margin: 0 5px;">대기</div>
						</c:if>
						</div>
						<li style="width: 100%; border-left: none;"></li>
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