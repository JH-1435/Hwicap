<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<jsp:include page="../head.jsp"></jsp:include>
<script type="text/javascript">	
window.onload = function() {
	//리뷰 가 하나도 없으면 hidden 처리 아니면 값을 보여줌
    var reviewCounts = [];
    <c:forEach var="item" items="${list}" varStatus="status">
        reviewCounts[<c:out value="${status.index}"/>] = <c:out value="${reviewTotals[item.keycapNum]}"/>;
    </c:forEach>
    reviewCounts.forEach(function(reviewCount, index) {
        if (reviewCount >= 1) {  // 리뷰 수가 1 이상이면
            document.getElementById('reviewInfo' + index).classList.remove('hidden');  // 해당 리뷰 정보의 hidden 클래스를 제거
        }
    });
    
    // 현재 웹 페이지의 URL을 가져옴
    var currentUrl = new URL(window.location.href);
     
    // URL에서 'keyword'와 'sort' 파라미터를 가져옴
    var keyword = currentUrl.searchParams.get('keyword');
    var sort = currentUrl.searchParams.get('sort');
    
    // 페이지네이션 링크를 모두 가져옴
    var pageLinks = document.querySelectorAll('.page-nation a');
	
    // 가져온 링크들에 대해 반복문을 실행
    pageLinks.forEach(function(link) {
      // 각 링크에 클릭 이벤트 리스너를 추가합니다.
      link.addEventListener('click', function(event) {
     	// 클릭한 링크의 URL을 가져오고, 그 URL의 'page' 파라미터 값을 가져옴
        var linkUrl = new URL(link.getAttribute('href'), currentUrl);
        var page = linkUrl.searchParams.get('page');

        // 클릭한 링크의 URL에 'keyword'와 'sort' 파라미터를 추가
        if (keyword) {
       		linkUrl.searchParams.set('keyword', keyword);
        }
        if (sort) {
            linkUrl.searchParams.set('sort', sort);
        }

        // 'page' 파라미터를 설정
        linkUrl.searchParams.set('page', page);

        // 클릭한 링크의 href 속성을 업데이트 함
        link.setAttribute('href', linkUrl.toString());
       });
    });

    // 정렬 순서 변경 링크를 모두 가져옴
    var sortLinks = document.querySelectorAll('#newProductLink, #reviewLink, #bestLink, #descLink, #ascLink');

    // 가져온 링크들에 대해 반복문을 실행합니다.
    sortLinks.forEach(function(link) {
    	// 각 링크에 클릭 이벤트 리스너를 추가
        link.addEventListener('click', function(event) {
        	// 클릭한 링크의 URL을 가져옵니다.
        	var linkUrl = new URL(link.getAttribute('href'), currentUrl);

            // 클릭한 링크의 URL에 'keyword' 파라미터를 추가하고 'page' 파라미터를 1로 설정
            if (keyword) {
            	linkUrl.searchParams.set('keyword', keyword);
            }
            linkUrl.searchParams.set('page', 1);

            // 클릭한 링크의 href 속성을 업데이트 함
            link.setAttribute('href', linkUrl.toString());
           });
       });  
    
  	//링크의 style 변경
    for (var i = 0; i < sortLinks.length; i++) {
    	var keycapLink = sortLinks[i];
    	var linkUrl = new URL(keycapLink.getAttribute('href'), currentUrl);
        var linkSort = linkUrl.searchParams.get('sort');

        if (sort == linkSort) { // 'sort' 파라미터만 비교
            keycapLink.style.fontWeight  = 'bold';
            keycapLink.style.color = '#000';
        } else {
            keycapLink.style.fontWeight = 'normal';
            keycapLink.style.color = '#888';
        }
    }
};         
// 검색 버튼 클릭 이벤트
function submitFormKeycap() {
        var keyword = $('#keycapSearchForm input[name="keyword"]').val();
        if (keyword) {
            window.location.href = '/keycap/list?sort=null&keyword=' + keyword;
        }
    }
//$(document).ready(function()는 HTML 요소들이 모두 로드된 후에 JavaScript 코드가 실행된다.    
$(document).ready(function() {
    $('#keycapSearchForm').on('submit', function(e) {
        e.preventDefault();
        var keyword = $(this).find('input[name="keyword"]').val();
        if (keyword) {
            window.location.href = '/keycap/list?sort=null&keyword=' + keyword;
        }
    });
});
</script>
<meta charset="UTF-8">
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<c:if test="${sessionScope.admin != null}">
<div class="left-wrap">
	<h4 class="content-h4" style="line-height: 28px; color: #333;">관리자 메뉴</h4>
	<ul class="admin-list-nav">	
		<c:if test="${sessionScope.admin.adminId == 'admin'}">
			<li><a href="/admin/list">관리자관리</a></li>
		</c:if>
	    <li><a href="/user/list">회원관리</a></li>
		<li><a href="/orders/listAdmin">주문관리</a></li>
		<li><a href="/board/listAdmin">문의관리</a></li>
		<li><a href="/keycap/add">상품등록</a></li>
		<li><a href="/keycap/list?sort=null" class="on">상품관리</a></li>
	</ul>
</div>
</c:if>
<!-- @@@@@@@@@@@@@@@@ CSS @@@@@@@@@@@@@@@@@@ -->
<div id="container-wrap">
	<div class="contents">
		<div class="mypage-header" style="text-align: left;">
			<h4 class="content-h4">키캡</h4>
		</div>
		<div style="margin-top: 20px;"></div>
		<!------ 컨텐츠 내용 ------>
		<div class="board-top">
		<!-- 순서 버튼  -->
		<div id="keycapLinkList" style="text-align: left;">
			<a id="newProductLink" href="/keycap/list?sort=null" class="keycapLink">신상품순 |</a>
			<a id="bestLink" href="/keycap/list?sort=best" class="keycapLink"> 인기도순 |</a>
			<a id="descLink" href="/keycap/list?sort=desc" class="keycapLink"> 높은가격순 |</a>
			<a id="ascLink" href="/keycap/list?sort=asc" class="keycapLink"> 낮은가격순 |</a>
			<a id="reviewLink" href="/keycap/list?sort=reviews" class="keycapLink"> 리뷰많은순</a>
		</div>
			<ul class="announcement-list">
				<!-- varStatus="status"로 각 항목에 index를 부여 할 수 있게됨 -->
				<c:forEach var="item" items="${list}" varStatus="status">
					<li class="announcement-list-li">
						<div class="announcement-item">
							<a href="${item.keycapNum}/keycapView">
							<img src="/HwicapUpload/${item.keycapImg}" class="announcement-avatar"></a>
							<div class="announcement-item-s">
								<strong><span class="announcement-item-sp">가격: </span><fmt:formatNumber value="${item.keycapPrice}" pattern="#,###" /></strong>
							</div>
							<div class="announcement-item-s">	
								<strong><span class="announcement-item-sp">상품명: </span>${item.keycapName}</strong>
							</div>
							<div class="announcement-item-s">
								<i class="fas fa-heart" style="color: #f33;"></i>
								<span class="heartColor"><fmt:formatNumber value="${item.keycapLike}" pattern="#,###"/></span>
							</div>
							<!-- div에 인덱스(순서)를 부여 -->
							<div class="announcement-item-s hidden" id="reviewInfo${status.index}">	
								<!-- averageStars 맵에서 keycapNum에 해당하는  별점 평균을 가져옴 -->
								<span class="announcement-item-sp">평점 : ${averageStars[item.keycapNum]} | </span>
								<!-- reviewTotals 맵에서 keycapNum에 해당하는 리뷰의 총 수를 가져옴 -->
								<span class="announcement-item-sp">리뷰 수 : ${reviewTotals[item.keycapNum]}</span> 
							</div>
							<div class="announcement-item-s">
								<c:if test="${sessionScope.admin.adminState == 1 }">
									<strong><span class="announcement-item-sp">관리: </span>
									<button type="button" onclick="location.href = '${item.keycapNum}/delete';" style="cursor: pointer;">삭제</button>
									<button type="button" onclick="location.href = '${item.keycapNum}/update';" style="cursor: pointer;">수정</button></strong>
								</c:if>
							</div>
						</div>
					</li>
					</c:forEach>
				</ul>
						<c:if test="${list.size() < 1}">
							<div class="announcement-list2">
								<div class="announcement-list2-textbox">
									<strong>입력하신 <span style="color:#6b90dc">'${pager.keyword}'</span>에 대한 스토어 내 검색결과가 없습니다.</strong>
									<ul>
										<li>일시적으로 상품이 품절되었을 수 있습니다.</li>
										<li>단어의 철자가 정확한지 확인해 주세요.</li>
										<li>보다 일반적인 검색어로 다시 검색해 보세요. </li>
										<li>검색어의 띄어쓰기를 다르게 해보세요(예: 성난원숭이 > 성난 원숭이)</li>
									</ul>
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
	</div>
	<c:if test="${sessionScope.admin.adminState == 1}">
		<div class="overflow-hidden">
			<div class="btn-group">
					<a href="add" class="admin-btn"><i class="fas fa-file-signature"></i>상품등록</a>
					<a href="dummy" class="admin-btn"><i class="far fa-plus-square"></i>더미등록</a>
					<a href="init" class="admin-btn"><i class="far fa-trash-alt"></i>초기화</a>			
			</div>
		</div>
	</c:if>
			</div>
	</div>
	<div class="clear"></div>
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