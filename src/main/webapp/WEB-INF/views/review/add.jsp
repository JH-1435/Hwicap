<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<c:set var="contextPath" value="${pageContext.request.contextPath}"  />
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="../head.jsp"></jsp:include>
<!-- CKEDITOR_5_review.js 를 절대경로 방식으로 불러옴 -->
<script src="/js/CKEDITOR_5_review.js"></script>
<script type="text/javascript">	
//리뷰 별점 색채우기
$(document).ready(function(){
	  $('.rating input').click(function () {
	    $(this).nextAll('input').prop('checked', false);
	  });
	});
	
function submitForm() {
	$('#reviewForm').submit();
	}
</script>
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<div id="container-wrap">
		<div class="contents">
			<div class="board-top">
			<div class="mypage-header" style="text-align: left;">
				<h4 class="content-h4">후기 작성</h4>
			</div>
			<ul class="info-text">
				<li style="color: red;">상품과 관련 없는 내용(사진/동영상 포함), 동일 문자의 반복 등을 포함한 의미없는 후기, 욕설/비방 등의 악의적인 내용을 포함한 후기, 부정거래에 기반하여 작성된 후기는 통보없이 삭제됩니다.</li>
				<li>작성하신 후기는 Hwicap 및 Hwicap 글로벌 이용자에게 공개됩니다.</li>
			</ul>
			<form id="reviewForm" method="post">
				<table class="mypage-table" style="border-top: none;">
				<colgroup>
					<col style="width:14.2%">
					<col style="width:*">
				</colgroup>
					<thead>
						<c:forEach var="keycap" items="${orders.keycap}"> <!-- orders.xml에 있는 keycap에 접근할 수 있다. -->
						<tr>
						<td style="padding-left: 40px; border-bottom: 1px solid #000000;">
						<div class="announcemen-box">
							<a href="/keycap/${orders.keycapNum}/keycapView" class="img-block">
								<img src="/HwicapUpload/${orders.orderImg}" alt="${orders.orderImg}" style="top: 50%; transform: translateY(-50%);">
								<input type="hidden" id="keycapNum" name="keycapNum" value="${orders.keycapNum}">
							 	<input type="hidden" id="orderSeqNum" name="orderSeqNum" value="${orders.orderSeqNum}">
							</a>
						</div>
						</td>
						<td style="padding-left: 0; border-bottom: 1px solid #000000;">
						<div class="announcemen-box">
							<ul class="info">
								<li class="category"><a href="/keycap/list?sort=null">${keycap.keycapCategory}</a></li>
								<li class="name"><a href="/keycap/${orders.keycapNum}/keycapView">${orders.keycapName}</a></li>
							</ul>
						</div>
						</td>
					</tr>
					</c:forEach>
					</thead>
					<!---- 상품 후기 작성 ---->
					<tbody>
					<tr style="text-align: left; border-bottom: 1px solid #000000;">
						<th style="padding-left: 40px; background: #f7f8f9;">별점을 매겨주세요</th>
							<td class="rating-container" style="text-align: left; border-bottom: none; width: 100%; margin-left: 45px; justify-content: left; padding: 0;">
								<fieldset class="rating">
							      <input type="radio" id="star5" name="reviewStar" value="5" /><label for="star5"></label>
							      <input type="radio" id="star4" name="reviewStar" value="4" /><label for="star4"></label>
							      <input type="radio" id="star3" name="reviewStar" value="3" /><label for="star3"></label>
							      <input type="radio" id="star2" name="reviewStar" value="2" /><label for="star2"></label>
							      <input type="radio" id="star1" name="reviewStar" value="1" /><label for="star1"></label>
							    </fieldset>
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9; color: #333;">후기 내용</th>
							<td style="border-bottom: none; width: 100%;">
								<textarea rows="200" cols="200" name="reviewContent" id="reviewContent" maxlength="2048" placeholder="다른 회원분에게 도움이 되는 나만의 팁을 소개해 주세요."></textarea>
							</td>
						</tr>
					</tbody>
					</table>
					<div class="overflow-hidden">
						<div class="btn-group">
							<a onclick="event.preventDefault(); submitForm();" class="end-btn">작성완료</a>
							<a href="/orders/${sessionScope.user.userId}/list" class="end-btn">취소</a>
						</div>
					</div>
				</form>
		</div>
	<!-- contents-layout  -->
	<div class="clear"></div>
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