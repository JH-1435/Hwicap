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
	<div class="contents">
			<div class="board-top">
				<div class="procedure" style="margin-top: 5%;">
					<img src="/img/main-bottom.png" style="max-width: 1260px;">
				</div>
				<div class="mypage-header" style="text-align: left;">
					<h4 class="content-h4">1:1 문의</h4>
				</div>
				<ul class="QnA-list">
						<li class="QnA-text" style="color: red;">제품 사용, 오염, 전용 박스 손상, 라벨 제거, 사은품 및 부속 사용/분실 시, 교환/환불이 불가능 합니다.</li>
						<li class="QnA-text" style="color: red;">교환을 원하시는 상품(사이즈)의 재고가 부족 시, 교환이 불가합니다.</li>
						<li class="QnA-text">1:1문의 처리 내역은 마이페이지 > 문의내역을 통해 확인하실 수 있습니다.</li>
						<li class="QnA-text">상품 정보(사이즈, 예상 배송일 등) 관련 문의는 해당 상품 문의에 남기셔야 빠른 답변이 가능합니다.</li>
				</ul>
				<!---- 1:1 상품 QnA 작성 ---->
				<form id="boardForm" method="post">
				<table class="mypage-table">
				<colgroup>
					<col style="width:14.2%">
					<col style="width:*">
				</colgroup>
					<thead>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
						<th style="padding-left: 40px; background: #f7f8f9;">문의 유형</th>
							<td style="text-align: left; border-bottom: none; width: 100%; padding: 15px;">
								<input class="boardTitle" type="radio" name="boardTitle" value="주문제작 문의" checked="checked">주문제작문의
								<input class="boardTitle" type="radio" name="boardTitle" value="배송 문의">배송
								<input class="boardTitle" type="radio" name="boardTitle" value="취소/교환/환불 문의">취소/교환/환불
								<input class="boardTitle" type="radio" name="boardTitle" value="회원정보 문의">회원정보
								<input class="boardTitle" type="radio" name="boardTitle" value="상품상세 문의">상품상세문의
							</td>
						</tr>
					</thead>
					<tbody>
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
						<a href="/" class="end-btn">취소</a>
					</div>
				</div>
				</form>
		</div>
		</div>
		</div>
		<!-- contents-layout  -->
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