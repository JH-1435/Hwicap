<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="../head.jsp"></jsp:include>
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
<div id="container-wrap">
	<div class="contents">
		<div class="mypage-header" style="text-align: left;">
			<h4 class="content-h4">관리자 관리</h4>
		</div>
		<ul class="info-text">
			<li style="color: red;">해당 관리자 관리 페이지는 최상위 관리자 만 열람 가능합니다.</li>
			<li style="color: red;">관리자의 권한을 주거나 박탈 하거나 삭제 할 수 있습니다.</li>
		</ul>
		<div style="margin-top: 20px;"></div>
		<!------ 컨텐츠 내용 ------>
		<div class="board-top">
		<div class="search-list">
			<form method="get" action="">
			<div class="search-index">
				<span class="search-button">
					<select name="search">
						<option value="0">선택</option>
						<option value="1" ${pager.search == 1 ? 'selected' : ''}>아이디</option>
						<option value="2" ${pager.search == 2 ? 'selected' : ''}>이름</option>
					</select>
				</span>
				<span class="search-keyword">
					<input type="text" name="keyword" placeholder="검색어를 입력해 주세요" value="${pager.keyword}">
				</span>
				<span class="search-button">
					<input type="submit" value="조회하기" class="button">
				</span>
			</div>
			</form>
		</div>
		<table class="mypage-table">
		<colgroup>
			<col style="width:14.2">
			<col style="width:14.2%">
			<col style="width:14.2%">
			<col style="width:*">
			<col style="width:14.2%">
		</colgroup>		
		<thead>
			<tr>
				<th scope="col">아이디</th>
				<th scope="col">이름</th>
				<th scope="col">관리자 여부</th>
				<c:if test="${sessionScope.admin.adminId == 'admin'}">
					<th scope="col">비밀번호</th>
					<th scope="col">관리</th>
				</c:if>
			</tr>
		</thead>
		<tbody>
		<c:if test="${list.size() < 1}">
			<tr>
				<td colspan="5">등록 된 관리자 가 없습니다</td>
			</tr>
		</c:if>
		<c:if test="${list != null && list.size() >= 1}">
		<c:forEach var="item" items="${list}">
			<tr class="mypage-trHover">
				<td>${item.adminId}</td>
				<td>${item.adminName}</td>
				<c:if test="${item.adminState == 1}">
					<td><span style="color: #0078ff;">승인</span></td>
				</c:if>
				<c:if test="${item.adminState != 1}">
					<td><span>대기(박탈)</span></td>
				</c:if>
				<td>${item.adminPw}</td>
				<td>
					<a href="/admin/${item.adminId}/update" class="r-link state" style="cursor:pointer;">수정 </a>  
					<c:if test="${item.adminId != 'admin'}">
						<span style="color: #777777; margin: 0 5px;">|</span>
						<a href="/admin/${item.adminId}/delete" class="r-link state" style="cursor:pointer;">삭제</a>
					</c:if>
				</td>
			</tr>
		</c:forEach>
		</c:if>
		</tbody>
		</table>
		<c:if test="${sessionScope.admin.adminId == 'admin' }">
			<div class="overflow-hidden">
				<div class="btn-group">
					<a href="add" class="admin-btn"><i class="fas fa-file-signature"></i>등록</a>
				</div>	
			</div>
		</c:if>	
		<div id="page-wrap">		
			<div class="group-page">
				<ul class="page-nation">
				<!-- 페이지는 10개씩 보여주므로 페이지번호 11번 이후 부터는 이전버튼 보이도록 설정 -->
				<c:if test="${pager.page gt 10}" >
					<li><a class="page-nation-prev" href="?page=${pager.prev}&${pager.query}">
					<img src="/resources/img/page_prev.png"> &nbsp; 이전 </a></li>
				</c:if>
				<c:forEach var="page" items="${pager.list}">
					<li id="pager-list" class="${page == pager.page ? 'active' : ''}">
					<a href="?page=${page}&${pager.query}">${page}</a></li>
				</c:forEach>
				<!-- fmt:parseNumber로 소수점을 버려줌, 페이지는 10개씩 보여주는데, 만약 마지막 페이지번호가 35라면 31번째 페이지번호 이후부터 다음버튼이 안보이게 설정  -->
				<fmt:parseNumber var="pageSum" value="${(pager.page / 10) - 0.1}" integerOnly="true"/>
				<fmt:parseNumber var="lastSum" value="${pager.getLast() / 10 - 0.1}" integerOnly="true"/>
				<c:if test="${pageSum lt lastSum}" >
					<li><a class="page-nation-prev" href="?page=${pager.next}&${pager.query}">다음 &nbsp;
					<img src="/resources/img/page_next.png"></a></li>
				</c:if>
				</ul>
			</div>
		</div>
		<!-- 검색 시 데이터값이 없을시 확인 -->
		<c:if test="${list != null && list.size() < 1 && pager.keyword != null}">
			<div class="announcement-list2">
				<div class="announcement-list2-textbox">
					<strong>입력하신 <span style="color:#6b90dc">'${pager.keyword}'</span>에 대한 주문내역내 검색결과가 없습니다.</strong>
					<ul>
						<li>단어의 철자가 정확한지 확인해 주세요.</li>
						<li>보다 일반적인 검색어로 다시 검색해 보세요. </li>
						<li>검색어의 띄어쓰기를 다르게 해보세요(예: 성난원숭이 > 성난 원숭이)</li>
					</ul>
				</div>
			</div>
		</c:if>
	</div>
	</div>
	</div>
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