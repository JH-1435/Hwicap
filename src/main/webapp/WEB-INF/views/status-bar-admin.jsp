<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<div class="status-bar">
	<div class="search-list">
			<div class="search-index" style="visibility: hidden;">
				<div id="search-container" style="visibility: hidden;">
					<div id="status-bar-search" style="visibility: hidden;"></div>
				</div>
			</div>
		<!-- sessionScope => 세션(session -> user가 저장되어있음)에  저장되어있는(Scope)를  불러옴 -->
		<c:if test="${sessionScope.admin != null}">
			<div class="status-bar-login">
				<div><a href="/indexAdmin" id="login-admin02" class="status-bar-a">관리자 메인페이지로</a>
				(${sessionScope.admin.adminName})님<a href="/logout" class="status-bar-a">로그아웃</a></div>
			</div>
		</c:if>
	</div>
	<div class="nav">
        <div class="logo-container">
            <a href="/"><img src="/img/logo-main.png" class="logo"/></a>
        </div>
        <div class="nav-list-container">
            <ul class="nav-list">
                <c:if test="${sessionScope.admin.adminId == 'admin'}">
					<li><a href="/admin/list">관리자관리</a></li>
				</c:if>
                <li><a href="/user/list">회원관리</a></li>
				<li><a href="/orders/listAdmin">주문관리</a></li>
				<li><a href="/board/listAdmin">문의관리</a></li>
				<li><a href="/keycap/add">상품등록</a></li>
				<li><a href="/keycap/list?sort=null">상품관리</a></li>
            </ul>
        </div>
    </div>
</div>
