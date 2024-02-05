<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<jsp:include page="../head.jsp"></jsp:include>
<meta charset="UTF-8">
<script type="text/javascript">	
function submitForm() {
	$('#confirmationForm').submit();
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
			<li><a href="/admin/list">관리자관리</a></li>
		</c:if>
	    <li><a href="/user/list">회원관리</a></li>
		<li><a href="/orders/listAdmin" class="on">주문관리</a></li>
		<li><a href="/board/listAdmin">문의관리</a></li>
		<li><a href="/keycap/add">상품등록</a></li>
		<li><a href="/keycap/list?sort=null">상품관리</a></li>
	</ul>
</div>
<!-- @@@@@@@@@@@@@@@@ CSS @@@@@@@@@@@@@@@@@@ -->
<div id="container-wrap">
	<div class="contents">
		<div class="mypage-header" style="text-align: left;">
			<h4 class="content-h4">주문관리</h4>
		</div>
		<ul class="info-text">
			<li style="color: red;">해당 주문관리 페이지는 관리자 만 열람 가능합니다.</li>
			<li>주문자의 배송상태를 관리 할 수 있습니다.</li>
			<li>간편 로그인 회원은 Naver_ , Kakao_ , Google_ 등 으로 표기됩니다.</li>
		</ul>
		<div style="margin-top: 20px;"></div>
		<!------ 컨텐츠 내용 ------>
		<div class="board-top">
		<!-- 주문내역 list 비었는지 확인 -->
		<c:if test="${list != null && list.size() < 1 && pager.keyword == null}">
			<div style="margin-top: 30px;">
				<div><strong>유저가 주문한 상품이 없습니다.</strong></div>
			</div>
		</c:if>	
		<c:if test="${list != null && list.size() >= 1}">
		<div class="search-list">
			<form method="get" action="">
			<div class="search-index">
				<span class="search-keyword" style="margin-right: 5px;">
					<select name="search" style="width: 100%; height: 30px;">
						<option value="2" ${pager.search == 2 ? 'selected' : ''}>주문자ID</option>
						<option value="1" ${pager.search == 1 ? 'selected' : ''}>상품명</option>
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
			<col style="width:30.2%">
			<col style="width:5%">
			<col style="width:14.2%">
			<col style="width:10.2%">
			<col style="width:22.2%">
			<col style="width:9.1%">
		</colgroup>	
		<thead>
			<tr>
				<th scope="col">상품정보</th>
				<th scope="col">주문번호</th>
				<th scope="col">주문자(이름)</th>
				<th scope="col">결제일자</th>
				<th scope="col">주문금액(수량)</th>
				<th scope="col" colspan="2">주문상태</th>
			</tr>
		</thead>
		<tbody>
		<c:forEach var="item" items="${list}">
		<c:forEach var="keycap" items="${item.keycap}"> <!-- orders.xml에 있는 keycap에 접근할 수 있다. -->
		<tr class="mypage-trHover">
			<td>
				<div class="announcemen-box">
					<a href="/keycap/${item.keycapNum}/keycapView" class="img-block">
						<img src="/HwicapUpload/${item.orderImg}" alt="${orders.orderImg}">
					</a>
					<ul class="info">
						<li class="category"><a href="/keycap/list?sort=null">${keycap.keycapCategory}</a></li>
						<li class="name"><a href="/keycap/${item.keycapNum}/keycapView">${item.keycapName}</a></li>
					</ul>
				</div>
			</td>
			<td>${item.orderSeqNum}</td>
			<td>
				${item.userId}
				<br>
				(<strong style="color: #333;">${item.userName}</strong>)님
			</td>
			<td><fmt:formatDate value="${item.orderPayDate}" pattern="yyyy-MM-dd"/></td>
			<td><fmt:formatNumber value="${item.orderPrice}" pattern="#,###"/>원<br>
				<span class="text-default">${item.orderStock}개</span>
			</td>
			<td>${item.orderState}</td>
			<c:if test="${item.orderState != '결제완료'}">		
				<td>&nbsp;</td>
			</c:if>
			<c:if test="${item.orderState == '결제완료'}">	
				<td>
				<form id="confirmationForm" method="post" action="/orders/${item.orderSeqNum}/updateMsg">
					<input name="orderState" type="hidden" value="001">
					<input name="keycapNum" type="hidden" value="${item.keycapNum}">
					<input name="orderStock" type="hidden" value="${item.orderStock}">
				</form>
					<a onclick="event.preventDefault(); submitForm();" class="mypage-btn-review" style="cursor:pointer;">배송확정</a>
				</td>
			</c:if>
		</tr>
		</c:forEach>	
		</c:forEach>
		</tbody>
	</table>
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
	</c:if>	
	<!-- 검색 시 데이터값이 없을시 확인 -->
	<c:if test="${list != null && list.size() < 1 && pager.keyword != null}">
		<div class="announcement-list2">
			<div class="announcement-list2-textbox">
				<strong>입력하신 <span style="color:#6b90dc">'${pager.keyword}'</span>에 대한 주문관리 내역내 검색결과가 없습니다.</strong>
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