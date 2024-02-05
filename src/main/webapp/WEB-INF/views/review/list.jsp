<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<c:set var="contextPath" value="${pageContext.request.contextPath}"  />
<!DOCTYPE html>
<html>
<head>
<jsp:include page="../head.jsp"></jsp:include>	
<script type="text/javascript">
//더보기 기능, 페이지가 로드되면 이벤트를 등록(html이 완전히 로딩 된 후에 dom 실행)
document.addEventListener("DOMContentLoaded", function() {
	// class="ckeditor_content" 요소를 모두 찾음
	var editorContents = document.querySelectorAll('.ckeditor_content');

	// 찾은 class="ckeditor_content" 요소마다 반복처리
	editorContents.forEach(function(editorContent) {
	    // class="photo-box" 요소를 모두 찾음
	    var allImages = editorContent.querySelectorAll('.photo-box');
	    
	 	// class="photo-box" 요소가 1개 이상 있을 때만 처리(이미지가 한 개 이상이면 처리)
	    if (allImages.length >= 1) {
	        // 총 이미지 수를 표시하는 span 요소를 생성
	        var imageCount = document.createElement('span');
	        imageCount.className = 'total-image-count'; 
	        imageCount.innerText = allImages.length;
	        imageCount.style.right = '0';

	        // 첫 번째 class="announcement-review" 요소를 찾음
	        var firstAnnouncementReview = editorContent.querySelector('.announcement-review');

	        /* class="announcement-review" 요소가 있으면 그 바로 뒤에 총 이미지 수를 삽입하고,
	               없으면 class="ckeditor_content" 요소의 마지막에 '총 이미지 수를 삽입'합니다. */
	        if (firstAnnouncementReview) {
	            firstAnnouncementReview.parentNode.insertBefore(imageCount, firstAnnouncementReview.nextSibling);
	        } else {
	            editorContent.appendChild(imageCount);
	        }
	        
	        // class="photo-box" 요소가 2개 이상 있을 때만 처리(이미지가 두개 이상이면 처리)
		    if (allImages.length >= 2) {
		    	imageCount.style.display = 'block';  // 처음에는 보이게 설정
		    	// 처음에 첫 번째 이미지만 보이게 설정
		        allImages[0].style.display = 'block';
		        for (var i = 1; i < allImages.length; i++) {
		            allImages[i].style.display = 'none';
		        } 
		     } else {
			 	// class="photo-box" 요소가 1개 이하일 때는 총 이미지 수를 숨김
			    imageCount.style.display = 'none';
				}
	    	}
	     	// 리뷰 '더보기', '접기' 기능 관련 요소
	        const reviewContentDiv = editorContent.querySelector('.p-reviewContent');
	        const moreSpan = editorContent.querySelector('.more');
	        const lessSpan = editorContent.querySelector('.less');
	        
	        // 토글 기능을 적용
	        var toggleState = false;
	        editorContent.addEventListener('click', function() {
	            allImages.forEach(function(box, index) {
	                var imgInBox = box.querySelector('img'); // box 안에 있는 img 태그를 가르킴
	                if (toggleState) {
	                    // 토글 상태가 true (모든 이미지가 보이는 상태)이면 첫 번째 이미지만 보이게 설정
	                    box.style.display = (index === 0) ? 'block' : 'none';
	                    imgInBox.style.width = '144px';
	                    imgInBox.style.height = '144px';
	                } else {
	                    // 토글 상태가 false (첫 번째 이미지만 보이는 상태)이면 모든 이미지가 보이게 설정
	                    box.style.display = 'block';
	                    imgInBox.style.width = '307px';
	                    imgInBox.style.height = 'auto';
	                }
	            });
	         	// 총 이미지 수 표시도 토글 설정
	            if (allImages.length >= 2) { // 이미지가 2개 이상인 경우에만 '총 이미지 수'를 표시
	                imageCount.style.display = (toggleState) ? 'block' : 'none';
	            }
	            // 토글 상태를 변경
	            toggleState = !toggleState;
	            
	         	// 리뷰 '더보기', '접기' 기능
				if(moreSpan.style.display != 'none') {
					reviewContentDiv.style.height = 'auto';
	                moreSpan.style.display = 'none';
	                lessSpan.style.display = 'inline';
				} else if(lessSpan.style.display != 'none') {
					reviewContentDiv.style.height = '60px';
	                lessSpan.style.display = 'none';
	                moreSpan.style.display = 'inline';
				}		         	
	        }); 
	});
	
	//리뷰 ...더보기, ...접기 초기 설정
	const contents = document.querySelectorAll('.ckeditor_content');
	contents.forEach(function(contentDiv) {
	  const reviewContentDiv = contentDiv.querySelector('.p-reviewContent');
	  const moreSpan = contentDiv.querySelector('.more');
	  const lessSpan = contentDiv.querySelector('.less');
	
	  if(reviewContentDiv && moreSpan && lessSpan) {
	    const originalHeight = reviewContentDiv.style.height;  // 원래 높이를 저장
	    reviewContentDiv.style.height = 'auto';  // 높이를 auto로 설정
	
	    if(reviewContentDiv.scrollHeight > 61) {  // 내용의 실제 높이를 체크
	      moreSpan.style.display = 'inline';
	      reviewContentDiv.style.height = '60px';  // 내용의 높이가 61px 이상일 경우에만 높이를 60px로 설정
	    } else {
	      reviewContentDiv.style.height = originalHeight;  // 내용의 높이가 56px 미만일 경우 원래 높이를 복원
	    }
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
<!-- @@@@@@@@@@@@@@@@ CSS @@@@@@@@@@@@@@@@@@ -->
<div id="container-wrap">
	<div class="contents">
	<div class="mypage-header">
		<h4 class="content-h4">My Page</h4>
		<ul class="mypage-list-ul">
			<li><a href="/orders/${sessionScope.user.userId}/list" class="mypage-list-href">주문내역 조회</a></li>
			<li style="color: #333; font-weight: 600;"><a href="/review/${sessionScope.user.userId}/list" class="mypage-list-href">구매후기</a></li>
			<li><a href="/board/${sessionScope.user.userId}/list" class="mypage-list-href">문의내역</a></li>
			<li><a href="/heart/${sessionScope.user.userId}/list" class="mypage-list-href">좋아요</a></li>
		</ul>
	</div>
	<ul class="info-text">
		<li style="color: red;">상품과 관련 없는 내용(사진/동영상 포함), 동일 문자의 반복 등을 포함한 의미없는 후기, 욕설/비방 등의 악의적인 내용을 포함한 후기, 부정거래에 기반하여 작성된 후기는 통보없이 삭제됩니다.</li>
		<li>작성하신 후기는 Hwicap 및 Hwicap 글로벌 이용자에게 공개됩니다.</li>
	</ul>
		<!------ 컨텐츠 내용 ------>
		<div class="a-table-view02">
		<!-- 리뷰 list 비었는지 확인 -->
		<c:if test="${list != null && list.size() < 1}">
			<div style="margin-top: 30px;">
				<div><strong>작성 가능한 후기가 없습니다.</strong></div>
				<div><a href="/keycap/list?sort=null" class="list-btn">쇼핑 계속하기 ></a></div>
			</div>
		</c:if>
		<c:if test="${list != null && list.size() >= 1}">
		<table class="mypage-table">
		<colgroup>
			<col style="width:30.2%">
			<col style="width:30.2%">
			<col style="width:15%">
		</colgroup>
		<thead>
			<tr>
				<th scope="col">상품정보</th>
				<th scope="col">내용</th>
				<th scope="col">후기 상태</th>
			</tr>
		</thead>
		<tbody>
		<c:forEach var="item" items="${list}">
		<c:forEach var="orders" items="${item.orders}"> <!-- review.xml에 있는 orders에 접근할 수 있다. -->
		<c:forEach var="keycap" items="${item.keycap}"> <!-- review.xml에 있는 keycap에 접근할 수 있다. -->
		<tr class="mypage-trHover">
			<td>
				<div class="announcemen-box">
					<a href="/keycap/${item.keycapNum}/keycapView" class="img-block">
						<img src="/HwicapUpload/${orders.orderImg}">
					</a>
					<ul class="info">
						<li class="category"><a href="/keycap/list?sort=null">${keycap.keycapCategory}</a></li>
						<li class="name"><a href="/keycap/${item.keycapNum}/keycapView">${orders.keycapName}</a></li>
					</ul>
				</div>
			</td>	
			<td style=" display: flex; justify-content: left; align-items: center; height: auto; position: relative;">
			<div class="announcemen-box">
			<ul class="info">
			<li><p><fmt:formatDate value="${item.reviewDate}" pattern="yyyy-MM-dd"/> | ${orders.orderState}</p></li>
			<li class="rating-container-review rating-container" style="justify-content: left;">
				<ul class="rating">
					<c:forEach var="i" begin="1" end="5">
						<c:choose>
							<c:when test="${i > 5 - item.reviewStar}">
								<li><i class="fa fa-star"></i></li>
							</c:when>
							<c:otherwise>
								<li><i class="far fa-star"></i></li>
							</c:otherwise>
						</c:choose>
					</c:forEach>
				</ul>
			</li>
			<!-- @@@ 리뷰내용(li) 클릭  > 모든 사진 나오고 다시 클릭하면 접음 @@@ -->
			<li class="ckeditor_content" style="cursor: pointer;">
				<div class="p-reviewContent" style="height: auto; white-space: normal; overflow: hidden;">
    				${item.reviewContent}
    			</div>
    			<div class="more" style="display: none; color: #aaa;">...더보기</div>
   				<div class="less" style="display: none; color: #aaa;">...접기</div>
			    <c:if test="${item.reviewImg != null}">
		            <c:set var="imgUrls" value="${fn:split(item.reviewImg, ';')}" />
		             <c:forEach varStatus="status" var="imgUrl" items="${imgUrls}">
		             	<div class="photo-box firstImage" style="${status.index == 0 ? '' : 'display: none;'}"> <!-- 처음 모든 이미지를 none으로 바꾸고 js에서 설정함 -->
		                	<div class="photo-big">
		                            <ul class="announcement-list" style="margin: 0 auto;">
		                                <li style="padding: 0;">
		                                    <img src="${imgUrl}" class="announcement-review">
		                                </li>
		                            </ul>
		                        </div>
		                    </div>
		                </c:forEach>
		            </c:if>
		        </li>
		        </ul>
		    	</div>
			</td>
			<td>
				<a href="/review/${item.reviewNum}/update" class="r-link state" style="cursor:pointer;">수정 </a>  
				<span style="color: #777777; margin: 0 5px;">|</span>
				<a href="/review/${item.reviewNum}/delete" class="r-link state" style="cursor:pointer;">삭제</a>
			</td>
			</tr>
			</c:forEach>
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