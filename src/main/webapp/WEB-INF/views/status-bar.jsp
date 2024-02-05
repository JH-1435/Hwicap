<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<script type="text/javascript">	
//검색 버튼 클릭 이벤트
function submitFormStatus() {
        var keyword = $('#statusSearchForm input[name="keyword"]').val();
        if (keyword) {
            window.location.href = '/keycap/list?sort=null&keyword=' + keyword;
        }
    }
    
//$(document).ready(function()는 HTML 요소들이 모두 로드된 후에 JavaScript 코드가 실행된다.    
$(document).ready(function() {
    $('#statusSearchForm').on('submit', function(e) {
        e.preventDefault();
        var keyword = $(this).find('input[name="keyword"]').val();
        if (keyword) {
            window.location.href = '/keycap/list?sort=null&keyword=' + keyword;
        }
    });
    
  	//로그인 버튼을 5초간 꾹 누르면 관리자 로그인 페이지로 이동
    var loginBtn = document.getElementById('login-btn');
    var pressTimer;

    loginBtn.addEventListener('mousedown', function() {
        pressTimer = window.setTimeout(function() {
            window.location.href = "/loginAdmin";
        }, 5000);
    });

    loginBtn.addEventListener('mouseup', function() {
        clearTimeout(pressTimer);
    });
    
});


</script>
<div class="status-bar">	
	<!-- 상단 상품검색  -->
	<div class="search-list">
			<form id="statusSearchForm" method="get" action="">
			<div class="search-index">
				<span id="search-container">
					<input id="status-bar-search" type="text" name="keyword" placeholder="검색어를 입력해 주세요" value="${pager.keyword}">
					<a class="search-icon" href="#" onclick="event.preventDefault(); submitFormStatus();"><i class="fas fa-search"></i></a>
				</span>
				</div>
			</form>
			<!-- sessionScope => 세션(session -> user가 저장되어있음)에  저장되어있는(Scope)를  불러옴 -->
		<c:if test="${sessionScope.admin != null}">
			<div class="status-bar-login">
				<div><a href="/indexAdmin" id="login-admin02" class="status-bar-a">관리자 메인페이지로</a>
				(${sessionScope.admin.adminName})님<a href="/logout" class="status-bar-a">로그아웃</a></div>
			</div>
		</c:if>
		<c:if test="${sessionScope.admin == null}">
		<c:if test="${sessionScope.user == null}">
		<div class="status-bar-login">
			<a href="/login" id="login-btn" class="status-bar-a">로그인</a>
			<a href="/signup" class="status-bar-a">회원가입</a> 
		</div>
		</c:if>
		<c:if test="${sessionScope.user != null}">
			<div class="status-bar-login">
				<div>(${sessionScope.user.userName})님<a href="/logout" class="status-bar-a">로그아웃</a> 
				<a href="/cart/${sessionScope.user.userId}/list" class="status-bar-a">장바구니</a> 
				<a href="/orders/${sessionScope.user.userId}/list" class="status-bar-a">마이페이지</a> <!-- 현재는 구매내역 -->
				</div>
			</div>
		</c:if>
	</c:if>
	</div>
    <div class="nav">
        <div class="logo-container">
            <a href="/"><img src="/img/logo-main.png" class="logo"/></a>
        </div>
        <div class="nav-list-container">
            <ul class="nav-list">
            	<li><a href="/">HOME</a></li>
                <li><a href="/keycap/list?sort=null">NEW</a></li>
                <li><a href="/keycap/list?sort=best">BEST</a></li>
                <c:if test="${sessionScope.user == null}">
                	<li><a href="/login">CONTACT</a></li>
                </c:if>
                <c:if test="${sessionScope.user != null}">
                	<li><a href="/board/${sessionScope.user.userId}/addCs">CONTACT</a></li>
                </c:if>
            </ul>
        </div>
    </div>
</div>
