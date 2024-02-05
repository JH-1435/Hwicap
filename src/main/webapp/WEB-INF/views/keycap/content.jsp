<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<c:set var="contextPath" value="${pageContext.request.contextPath}"  />
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="../head.jsp"></jsp:include>
<script src="//t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script type="text/javascript">	
//메인화면으로
function main() {
	$.ajax ({
		type : "get",
		async : false,
		url : "${contextPath}/keycap/contentInit",
		data : { name : "main" },
		success : function(data, textStatus) {
			if(data.trim()=='redirect:/') 
			{
				var link = '/';
				location.replace(link);
			}
			else
			{
				var link = '${contextPath}/keycap/list';
				location.replace(link);
			}
		},
		error : function(data, textStatus) {
			alert("에러가 발생했습니다." + data);
		},
		complete : function(data, textStatus) {
			//console.log(data);
			//alert("작업을 완료했습니다." + textStatus);
		}
	});
}

//결제 취소
function init() {
	$.ajax ({
		type : "get",
		async : false,
		url : "${contextPath}/keycap/contentInit",
		success : function(data, textStatus) {
			if(data.trim()=='redirect:/') 
			{
				var link = '/';
				location.replace(link);
			}
			else
			{
				var link = '${contextPath}/keycap/list';
				location.replace(link);
			}
		},
		error : function(data, textStatus) {
			alert("에러가 발생했습니다." + data);
		},
		complete : function(data, textStatus) {
			//console.log(data);
			//alert("작업을 완료했습니다." + textStatus);
		}
	});
}

//배송지 검색
function orderAddress_execDaumPostcode() {
    new daum.Postcode({
        oncomplete: function(data) {
            // 팝업에서 검색결과 항목을 클릭했을때 실행할 코드를 작성하는 부분.

            // 각 주소의 노출 규칙에 따라 주소를 조합한다.
            // 내려오는 변수가 값이 없는 경우엔 공백('')값을 가지므로, 이를 참고하여 분기 한다.
            var addr = ''; // 주소 변수
            var extraAddr = ''; // 참고항목 변수

            //사용자가 선택한 주소 타입에 따라 해당 주소 값을 가져온다.
            if (data.userSelectedType === 'R') { // 사용자가 도로명 주소를 선택했을 경우
                addr = data.roadAddress;
            } else { // 사용자가 지번 주소를 선택했을 경우(J)
                addr = data.jibunAddress;
            }

            // 사용자가 선택한 주소가 도로명 타입일때 참고항목을 조합한다.
            if(data.userSelectedType === 'R'){
                // 법정동명이 있을 경우 추가한다. (법정리는 제외)
                // 법정동의 경우 마지막 문자가 "동/로/가"로 끝난다.
                if(data.bname !== '' && /[동|로|가]$/g.test(data.bname)){
                    extraAddr += data.bname;
                }
                // 건물명이 있고, 공동주택일 경우 추가한다.
                if(data.buildingName !== '' && data.apartment === 'Y'){
                    extraAddr += (extraAddr !== '' ? ', ' + data.buildingName : data.buildingName);
                }
                // 표시할 참고항목이 있을 경우, 괄호까지 추가한 최종 문자열을 만든다.
                if(extraAddr !== ''){
                    extraAddr = ' (' + extraAddr + ')';
                }
                /*
                // 조합된 참고항목을 해당 필드에 넣는다.
                document.getElementById("orderAddress").value = extraAddr;
                */
            
            } else {
                document.getElementById("orderAddress").value += '';
            }

            // 우편번호와 주소 정보를 해당 필드에 넣는다. (주소에 주소 값 + 참고항목 값 을 넣어줌)
            document.getElementById('orderAddress_postcode').value = data.zonecode;
            document.getElementById("orderAddress").value = addr + extraAddr;
            // 커서를 상세주소 필드로 이동한다.
            document.getElementById("orderAddress_detailAddress").focus();
        }
    }).open();
}

//js가 dom 즉 html이 모두 로드된 이후 마지막에 적용
document.addEventListener('DOMContentLoaded', function() {
	//결제 방법 에 따라 특정 값이 변경
	var radioButton1 = document.getElementById('orderPay_card');
	var radioButton2 = document.getElementById('orderPay_phone');

	var hiddenEvent1 = document.getElementById('orderTelPlan_event');
	var hiddenEvent2 = document.getElementById('orderCardPlan_event');
	var hiddenEvent3 = document.getElementById('orderCard_event');
	
	var hiddenEvent4 = document.getElementById('orderTelPlan_tel');
	var hiddenEvent5 = document.getElementById('orderCardPlan');
	var hiddenEvent6 = document.getElementById('orderCard');
	
	
	function hide() {
	  if (radioButton1.checked) {
	    hiddenEvent1.style.display = 'none'; 
        hiddenEvent4.value = null;
	    hiddenEvent2.style.display = 'table-row';
        hiddenEvent5.value = 0;
	    hiddenEvent3.style.display = 'table-row';
        hiddenEvent6.value = "";
	  }
	  else if(radioButton2.checked) {
	    hiddenEvent1.style.display = 'table-row';
	    hiddenEvent2.style.display = 'none'; 
        hiddenEvent5.value = 0;
	    hiddenEvent3.style.display = 'none'; 
        hiddenEvent6.value = "";
	  }
	}
	radioButton1.addEventListener('change', hide);
	radioButton2.addEventListener('change', hide);
});
function submit(event) {
	// 각각의 input 값 가져오기
	let keycapNum = $('#keycapNum').val();
	let cartCount = $('#cartCount').val();
	let total = $('#total').val();
	let orderImg = $('#orderImg').val();
    let orderUserName = $('#orderUserName').val();
    let orderTel = $('#orderTel').val();
    let orderCall = $('#orderCall').val();
    let orderAddress = $('#orderAddress').val();
    let orderAddress_postcode = $('#orderAddress_postcode').val();
    let orderAddress_detailAddress = $('#orderAddress_detailAddress').val();
    let orderMsg = $('#orderMsg').val();
    let orderPay = $("input[name='orderPay']").val();
    let orderCard = $('#orderCard').val();
    let orderCardPlan = $('#orderCardPlan').val();
    let orderTelPlan = $("input[name='orderTelPlan']").val();
    
	$.ajax ({
		type : "get", //cartCheckValues 라는 List<String>형태의 데이터를 전송 post방식을 써야함
		traditional: true, // 배열을 전송할 때 이 옵션을 true로 설정(jQuery에서 제공하는 AJAX 설정 중 하나이며 이 옵션은 서버로 데이터를 전송할 때 배열이나 객체를 어떻게 직렬화할지를 결정)
		url : "${contextPath}/keycap/orders",
		data : {
			keycapNum : keycapNum,
			cartCount : cartCount,
			total : total,
            orderUserName : orderUserName,
            orderImg : orderImg,
			orderTel : orderTel,
			orderCall : orderCall,
			orderAddress : orderAddress,
			orderAddress_postcode : orderAddress_postcode,
			orderAddress_detailAddress : orderAddress_detailAddress,
			orderMsg : orderMsg,
			orderPay : orderPay,
			orderCard : orderCard,
			orderCardPlan : orderCardPlan,
			orderTelPlan : orderTelPlan
        },
		success : function(data, textStatus) {		
			if(data.trim()=='redirect:/') {
				var link = '/';
				location.replace(link);
			} else if(data.trim()=='ordersError') {
				alert("해당 상품이 품절되어 구매할 수 없습니다.");
				return;
			} else if(data.trim()=='ordersErrorTotal') {
				alert("주문수량 보다 상품수량이 더 적어 구매할 수 없습니다.");
				return;
			} else if(data.trim()=='redirect:/keycap/list') {
				var link = '/orders/${sessionScope.user.userId}/list';
				alert("결제완료");
				location.replace(link);
			}
		},
		error : function(data, textStatus) {
			alert("에러가 발생했습니다." + data);
		},
		complete : function(data, textStatus) {
			//console.log(data);
			//alert("작업을 완료했습니다." + textStatus);
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
	<!------ 컨텐츠 내용 ------>
	<div class="board-top">
	<div class="a-table view02">
	<!-- 구매하기 list 비었는지 확인 -->
		<c:if test="${sessionScope.content == null}">
			<div style="margin-top: 30px;">
				<div><strong>구매하기에 담긴 상품이 없습니다.</strong></div>
				<div><em>원하는 상품을  구매 해보세요!</em></div>
				<div><a href="/keycap/list?sort=null" class="list-btn">쇼핑 계속하기 ></a></div>
			</div>
		</c:if>
		<c:if test="${sessionScope.content != null && sessionScope.content.size() >= 1}">
			<!-- submit 하면 form 값을 @GM("/orders")로 보냄 -->
			<form name="keycapOrders" method="get" action="/keycap/orders" >
			<div class="mypage-header" style="text-align: left;">
				<h4 class="content-h4">배송정보</h4>
				<div class="signup-text" style="text-align: left; padding-bottom: 0; margin-top: 5px; margin-bottom: 5px;">
					<i class="fas fa-check"></i>
					<span>항목은 <span style="color: #333;">필수 입력</span> 항목입니다.</span>
				</div>
			</div>
			<div class="login-entry">
			<div class="signup-list" style="width: 100%;">
				<ul class="text">
					<li class="th" style="width: 200px;"><p>받는 이</p><i class="fas fa-check"></i></li>
					<li class="td">
						<input id="orderUserName" type="text" name="orderUserName" value="${user.userName}" style="width: 400px;">
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="width: 200px;"><p>연락처(휴대폰번호)</p><i class="fas fa-check"></i></li>
					<li class="td">
						<input id="orderTel" type="tel" name="orderTel" oninput="this.value = this.value.replace(/\D/g, '');" placeholder="'-'을 제외한 휴대폰번호를 입력해 주세요" maxlength="11" style="width: 400px;" >
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="width: 200px;"><p>연락처(유선번호)</p>
					<li class="td">
						<input id="orderCall" type="tel" name="orderCall" oninput="this.value = this.value.replace(/\D/g, '');" placeholder="'-'을 제외한 유선번호를 입력해 주세요" maxlength="11" style="width: 400px;">
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="height: 140px; width: 200px;"><p>배송지</p><i class="fas fa-check"></i></li>
					<li class="td">
						<div><input type="text" id="orderAddress_postcode" name="orderAddress_postcode" onclick="orderAddress_execDaumPostcode()" style="cursor: pointer; width: 210px;" oninput="this.value = this.value.replace(/[^ ]/g, '');" placeholder="우편번호"></div>
						<div style="position: relative; display: flex; padding-left: 10px;"><input type="button" onclick="orderAddress_execDaumPostcode()" value="주소검색" style="width: 180px; cursor: pointer;"><i class="fas fa-search search-icon" onclick="orderAddress_execDaumPostcode()" style="left: 35px; cursor: pointer;"></i></div>
						<div style="display: flex; flex-direction: column; margin-top: 20px;"><input type="text" id="orderAddress" name="orderAddress" onclick="orderAddress_execDaumPostcode()"  oninput="this.value = this.value.replace(/[^ ]/g, '');" placeholder="주소" style="cursor: pointer; width: 400px;"></div>
						<div style="display: flex; flex-direction: column; margin-top: 5px;"><input type="text" id="orderAddress_detailAddress" name="orderAddress_detailAddress" placeholder="상세주소" style="width: 400px;"></div>
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="height: 120px; width: 200px;"><p>부재 시 전달 메시지</p>
					<li class="td">
						<textarea id="orderMsg" rows="6" cols="59" name="orderMsg" maxlength="2048" style="margin-left: 1px; color: #333; border: 1px #ccc solid; width: 400px;"></textarea>
					</li>
				</ul>
			</div>
			</div>
			<div style="margin-top: 30px;"></div>
			<!-- 주문자 정보 (네이버,카카오,구글 로그인 에서 아이디 제외 다른 정보를 가져올려면 유료임..) -->
			<div class="mypage-header" style="text-align: left;">
				<h4 class="content-h4">주문자</h4>
			</div>
			<div class="login-entry">
			<div class="signup-list" style="width: 100%;">
				<ul class="text">
					<li class="th" style="width: 200px;"><p>아이디</p></li>
					<li class="td">
						<div style="width: 400px;">${user.userId}</div>
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="width: 200px;"><p>이름</p></li>
					<li class="td">
						<div style="width: 400px;">${user.userName}</div>
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="width: 200px;"><p>연락처</p></li>
					<li class="td">
						<div style="width: 400px;">${user.userTel}</div>
					</li>
				</ul>
				<ul class="text">
					<li class="th" style="width: 200px;"><p>이메일</p></li>
					<li class="td">
						<div style="width: 400px;">${user.userAddress}</div>
					</li>
				</ul>
			</div>
			</div>
			<div style="margin-top: 30px;"></div>	
			<div class="mypage-header" style="text-align: left;">
				<h4 class="content-h4">주문상품</h4>
			</div>
			<table class="mypage-table">
			<colgroup>
				<col style="width:*">
				<col style="width:16%">
				<col style="width:16%">
				<col style="width:16%">
			</colgroup>
			<thead>
				<tr>
					<th scope="col">상품명</th>
					<th scope="col">판매가</th>
					<th scope="col">수량</th>
					<th scope="col">배송비/배송형태</th>
				</tr>
			</thead>
			<tbody>
		<c:forEach var="item" items="${sessionScope.content}">		
		<tr class="mypage-trHover">
		<td>
			<div class="announcemen-box">
				<a href="/keycap/${item.key}/keycapView" class="img-block">
					<img src="/HwicapUpload/${item.value.keycapImg}">
					<input id="orderImg" type="hidden" name="orderImg" value="${item.value.keycapImg}">
					<input id="keycapNum" type="hidden" name="keycapNum" value="${item.key}">
				</a>
				<ul class="info">
					<li class="name">
						<a href="/keycap/${item.key}/keycapView">${item.value.keycapName}</a>
						<input id="keycapName" type="hidden" name="keycapName" value="${item.value.keycapName}">
					</li>
					<c:if test="${item.value.keycapStock >= 5 && sessionScope.content.size() >= 1}">
						<li class="category">재고 5개 이상</li>
					</c:if>
					<c:if test="${item.value.keycapStock >= 1 && sessionScope.content.size() >= 1 && item.value.keycapStock < 5}">
						<li class="category">재고 ${item.value.keycapStock}개 남음</li>
					</c:if>
					<c:if test="${item.value.keycapStock < 1 && sessionScope.content.size() >= 1}">
						<li class="category">품절</li>
					</c:if>
				</ul>
			</div>
		</td>
		<td><fmt:formatNumber value="${total}" pattern="#,###" />원
			<input id="total" class="total" type="hidden" name="total" value="${total}">
		</td>
		<td>
			${cartCount}개
			<input id="cartCount" type="hidden" name="cartCount" value="${cartCount}">
		</td>
		<td>
			<div>택배배송</div>
			<div style="font-size: 600; color: #333;">배송비무료</div>
			<diV>0원 이상 무료</diV>
		</td>		
		</tr>	
		</c:forEach>
		</tbody>
		</table>
		<div style="margin-top: 30px;"></div>
		<div class="mypage-header" style="text-align: left;">
			<h4 class="content-h4">결제수단</h4>
			<div class="signup-text" style="text-align: left; padding-bottom: 0; margin-top: 5px; margin-bottom: 5px;">
				<i class="fas fa-check"></i>
				<span>항목은 <span style="color: #333;">필수 입력</span> 항목입니다.</span>
			</div>
		</div>
		<div class="login-entry">
			<div class="signup-list" style="width: 100%;">
				<ul class="text">
					<li class="th" style="width: 200px;"><p>결제방법</p><i class="fas fa-check"></i></li>
					<li class="td">
						<div style="width: 400px; display: flex; justify-content: left;">
							<input id="orderPay_card" type="radio" name="orderPay" value="card" checked style="width: 15px; height: auto;">
							<div style="margin: 0 5px;">카드</div>
							<input id="orderPay_phone" type="radio" name="orderPay" value="phone" style="width: 15px; height: auto; margin-left: 10px;"/>
							<div style="margin: 0 5px;">휴대폰 결제</div>
						</div>
					</li>
				</ul>
				<ul class="text" id="orderCard_event">
					<li class="th" style="width: 200px;"><p>결제카드</p><i class="fas fa-check"></i></li>
					<li class="td">
						<div style="width: 400px;">
							<select id="orderCard" name="orderCard">
								<option value="">카드선택</option>
							    <option value="hana">하나</option>
								<option value="kakaoPay">카카오페이</option>
								<option value="nh">농협</option>
								<option value="bc">BC카드</option>
								<option value="toss">토스</option>
							</select>
						</div>
					</li>
				</ul>
				<ul class="text content-text" id="orderCardPlan_event">
					<li class="th" style="width: 200px;"><p>할부 개월 수</p><i class="fas fa-check"></i></li>
					<li class="td">
						<div style="width: 400px;">
							<select id="orderCardPlan" name="orderCardPlan">
								<option value="0">일시불</option>
								<option value="2">2개월 무이자</option>
								<option value="3">3개월 무이자</option>
								<option value="4">4개월</option>
								<option value="5">5개월</option>
								<option value="6">6개월 부분 무이자</option>
								<option value="7">7개월</option>
								<option value="8">8개월</option>
								<option value="9">9개월</option>
							  	<option value="10">10개월 부분 무이자</option>
								<option value="11">11개월</option>
								<option value="12">12개월 부분 무이자</option>
							</select>
						</div>
					</li>
				</ul>
				<ul class="text content-text" id="orderTelPlan_event" style="display: none;">
					<li class="th" style="width: 200px;"><p>휴대폰 결제번호</p><i class="fas fa-check"></i></li>
					<li class="td">
						<div style="width: 400px;">
							<input id="orderTelPlan_tel" type="tel" name="orderTelPlan" oninput="this.value = this.value.replace(/\D/g, '');" maxlength="11">
						</div>
					</li>
				</ul>
			</div>
		</div>
		</form>
		<div>
			<button onclick="submit(event)" id="order-btn"><fmt:formatNumber value="${total}" pattern="#,###"/>원 결제하기</button>
		</div>
	</c:if>
	</div>
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