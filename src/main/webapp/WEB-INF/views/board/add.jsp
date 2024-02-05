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
<script src="/js/CKEDITOR_5_board.js"></script>
<script type="text/javascript">	
function submitForm() {
	$('#boardForm').submit();
}
</script>
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<div id="container-wrap">
	<div class="contents-layout">
		<div class="contents">
			<div class="board-top">
			<div class="mypage-header" style="text-align: left;">
				<h4 class="content-h4">상품문의 작성</h4>
			</div>
			<ul class="info-text">
				<li style="color: red;">제품 사용, 오염, 전용 박스 손상, 라벨 제거, 사은품 및 부속 사용/분실 시, 교환/환불이 불가능 합니다.</li>
				<li style="color: red;">교환을 원하시는 상품(사이즈)의 재고가 부족 시, 교환이 불가합니다.</li>
			</ul>
			<form id="boardForm" method="post">
				<table class="mypage-table" style="border-top: none;">
				<colgroup>
					<col style="width:14.2%">
					<col style="width:*">
				</colgroup>
					<thead>
						<tr>
							<td style="padding-left: 40px; border-bottom: 1px solid #000000;">
							<div class="announcemen-box">
								<a href="/keycap/${keycap.keycapNum}/keycapView" class="img-block">
									<img src="/HwicapUpload/${keycap.keycapImg}" alt="${keycap.keycapImg}" style="top: 50%; transform: translateY(-50%);">
									<input type="hidden" id="keycapNum" name="keycapNum" value="${keycap.keycapNum}">
								</a>
							</div>
							</td>
							<td style="padding-left: 0; border-bottom: 1px solid #000000;">
							<div class="announcemen-box">
								<ul class="info">
									<li class="category"><a href="/keycap/list?sort=null">${keycap.keycapCategory}</a></li>
									<li class="name"><a href="/keycap/${keycap.keycapNum}/keycapView">${keycap.keycapName}</a></li>
								</ul>
							</div>
							</td>
						</tr>
					</thead>
					<!---- 상품 QnA 작성 ---->
					<tbody>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">문의 유형</th>
							<td style="text-align: left; border-bottom: none; width: 100%; padding: 15px;">
								<input class="boardTitle" type="radio" name="boardTitle" value="배송 문의" checked="checked">배송
								<input class="boardTitle" type="radio" name="boardTitle" value="재입고 문의">재입고
								<input class="boardTitle" type="radio" name="boardTitle" value="상품상세 문의">상품상세문의
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">문의 상세내용</th>
							<td style="border-bottom: none; width: 100%;">
								<textarea rows="3" cols="20" name="boardContent" id="boardContent" maxlength="2048" placeholder="접수된 문의를 순차적으로 답변을 드리고 있습니다. 문의내용을 상세히 기재해 주셔야 정확한 답변이 가능합니다. 문의하신 내용에 답변을 위해 전화로 연락을 드릴 수 있습니다. - 운영시간 : 오전 10시 ~ 오후 6시 (평일)"></textarea>
								<input type="hidden" id="boardImg" name="boardImg">
							</td>
						</tr>
					</tbody>
				</table>
				<div class="overflow-hidden">
					<div class="btn-group">
						<a onclick="event.preventDefault(); submitForm();" class="end-btn">작성완료</a>
						<a href="/keycap/${keycap.keycapNum}/keycapView" class="end-btn">취소</a>
					</div>
				</div>
			</form>
		</div>
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