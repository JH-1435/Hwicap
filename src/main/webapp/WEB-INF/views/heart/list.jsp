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
//찜하기 (data : {keycapNum : keycapNum} 즉 이 변수 값을 서버(controller)로 보냄)
function add_heart(keycapNum, index, heartTry) {
	// ${index}는 c:forEach 루프의 인덱스 변수(각각의 아이템을 따로따로 선택하기 위함)
	var heartElement = $("#heart-" + index);
	var heartValElement = $("#heartVal-" + index);
    var heartVal = heartValElement.val();
	$.ajax ({
		type : "post",
		async : false,
		url : "${contextPath}/keycap/heart",
		data : {keycapNum : keycapNum, heartTry : heartTry},
		success : function(data, textStatus) {
			if(data.trim()=='redirect:/login') {
				var result = confirm("로그인이 필요한 서비스입니다. \n로그인 하시겠습니까?");
				if(result)
				{
					var link = '/login';
					location.replace(link);
				}
				else
				{
					return
				}
			} else if(data.trim()=='add_success') {
				heartElement.removeClass("far fa-heart").addClass("fas fa-heart");
				heartValElement.val(++heartVal);
				heartElement.css('color', '#f33');
				heartValElement.css('color', '#f33');
				return;
				
			} else if(data.trim()=='already_existed') {
				heartElement.removeClass("fas fa-heart").addClass("far fa-heart");
				heartValElement.val(--heartVal);
				heartElement.css('color', '#000');
				heartValElement.css('color', '#000');
				return;
			}
		},
		error : function(data, textStatus) {
			alert("에러가 발생했습니다." + data);
		},
		complete : function(data, textStatus) {
			//console.log(data);
			//alert("하트작업을 완료했습니다." + textStatus);
		}
	});
}
</script>
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<!-- @@@@@@@@@@@@@@@@ CSS @@@@@@@@@@@@@@@@@@ -->
<div id="container-wrap">
	<div class="contents">
	<div class="mypage-header">
		<h4 class="content-h4">My Page</h4>
		<ul class="mypage-list-ul">
			<li><a href="/orders/${sessionScope.user.userId}/list" class="mypage-list-href">주문내역 조회</a></li>
			<li><a href="/review/${sessionScope.user.userId}/list" class="mypage-list-href">구매후기</a></li>
			<li><a href="/board/${sessionScope.user.userId}/list" class="mypage-list-href">문의내역</a></li>
			<li style="color: #333; font-weight: 600;"><a href="/heart/${sessionScope.user.userId}/list" class="mypage-list-href">좋아요</a></li>
		</ul>
	</div>
	<div style="margin-top: 50px;"></div>
		<!------ 컨텐츠 내용 ------>
		<div class="a-table-view02">
		<!-- 찜 list 비었는지 확인 -->
		<c:if test="${list != null && list.size() < 1 && pager.keyword == null}">
			<div>
				<div><strong>찜하신 상품이 없습니다.</strong></div>
				<div><em>원하는 상품을 찜해 보세요!</em></div>
				<div><a href="/keycap/list?sort=null" class="list-btn">쇼핑 계속하기 ></a></div>
			</div>
		</c:if>
		<c:if test="${list != null && list.size() >= 1}">
		<ul class="announcement-list">
		<c:forEach var="item" items="${list}" varStatus="status">
		<c:forEach var="keycap" items="${item.keycap}" > <!-- HeartVo에 있는 List<keycapVo>에 접근할 수 있다. -->
			<li>
				<div class="announcemen-box">
					<a href="/keycap/${item.keycapNum}/keycapView" class="img-block">
						<img src="/HwicapUpload/${keycap.keycapImg}">
					</a>
					<ul class="info">
						<li class="category"><a href="/keycap/list?sort=null">${keycap.keycapCategory}</a></li>
						<li class="name"><a href="/keycap/${item.keycapNum}/keycapView">${keycap.keycapName}</a></li>
						<li class="price"><fmt:formatNumber value="${keycap.keycapPrice}" pattern="#,###"/>원</li>
						<!-- 찜 버튼 -->
						<c:if test="${sessionScope.admin == null}">
						<li>
							<a href="javascript:add_heart('${item.keycapNum}','${status.index}', 1)">
							<!-- ${status.index}를 이용하여 i태그 각각에 다른 아이디 부여 -->
							<i id="heart-${status.index}" class="fas fa-heart" style="color: #f33;"></i>
								<output id="heartVal-${status.index}">
									<span class="heartColor"><fmt:formatNumber value="${keycap.keycapLike}" pattern="#,###"/></span>
								</output>
							</a>
						</li>
						</c:if>
					</ul>
				</div>
			</li>
				
		</c:forEach>
		</c:forEach>
		</ul>
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