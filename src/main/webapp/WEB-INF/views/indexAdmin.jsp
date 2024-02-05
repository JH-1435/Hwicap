<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<script>
  window.onload = function(){
    document.querySelector('a[href="/orders/listAdmin"]').click();
  };
</script>
<jsp:include page="head.jsp"></jsp:include>	
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="status-bar.jsp"></jsp:include>
</header>
<div class="left-wrap">
	<h4 class="content-h4" style="line-height: 28px; color: #333;">관리자 메뉴</h4>
	<ul class="admin-list-nav">	
		<c:if test="${sessionScope.admin.adminId == 'admin'}">
			<li><a href="/admin/list">관리자관리</a></li>
		</c:if>
	    <li><a href="/user/list">회원관리</a></li>
		<li><a href="/orders/listAdmin" class="on">주문관리</a></li>
		<li><a href="/board/listAdmin">문의관리</a></li>
		<li><a href="/keycap/add">상품등록</a></li>
		<li><a href="/keycap/list?sort=null">상품관리</a></li>
	</ul>
</div>
<div id="container-wrap">
	<div class="contents">
		<!------ 컨텐츠 내용 ------>
		<div class="board-top">
		</div>	
	</div>
</div>
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