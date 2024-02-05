<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<c:set var="contextPath" value="${pageContext.request.contextPath}"  />
<!DOCTYPE html>
<html>
<head>
<jsp:include page="../head.jsp"></jsp:include>	
<script src="//t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>
<script type="text/javascript">	
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
            document.getElementById('orderAddress_postcode').falue = data.zonecode;
            document.getElementById("orderAddress").value = addr + extraAddr;
            // 커서를 상세주소 필드로 이동한다.
            document.getElementById("orderAddress_detailAddress").focus();
        }
    }).open();
}

function submit(event) {
	// 체크된 값 서버(controller)에 넘기기
    let cartCheckValues = [];  
    $(".cartCheck").each(function()
    {
    	if ($(this).is(":checked")) {
            // 체크박스가 체크되어 있다면 그 값을 배열에 추가, 아니면 0으로 추가
            cartCheckValues.push($(this).val());
    	} else {
        	cartCheckValues.push(0);
        }
    });
	    
	// 배열의 모든 요소가 0인지 확인
	let allZeros = cartCheckValues.every(val => val === 0);
    if(allZeros)
    {
    	alert("최소 하나이상의 상품을 체크해주세요.");
    	return;
    }
    
    // 각각의 input 값 가져오기
    let cartNum = $('#cartNum').val();
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
		url : "${contextPath}/cart/ordersCart",
		data : {
			cartCheckValues : cartCheckValues,
            cartNum : cartNum,
            orderUserName : orderUserName,
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
				alert("장바구니내 상품이 품절되어 구매할 수 없습니다.");
				location.reload(); // 페이지 새로 고침
				return;
			} else if(data.trim()=='ordersErrorTotal') {
				alert("주문수량 보다 상품수량이 더 적어 구매할 수 없습니다.");
				location.reload(); // 페이지 새로 고침
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
	
	
    // 페이지 로드가 완료되면 실행(disable이 아닌 체크박스의 total 값을 모두 합산으로 넣음)
    let total_val = 0;
    $(".cartCheck:not(:disabled)").each(function() {
        let total = parseInt($(this).val().replace(/,/g, ""));
        total_val += total;
    });
    $(".total_val").val(total_val.toLocaleString('ko-KR'));
    
	//체크박스 전체 선택 (비활성화 된 체크(disabled 즉 품절 상품)는 빼고 전부 체크 함 )
	$(".all_check_input").on("click", function(){
	    let total_val = parseInt($(".total_val").val().replace(/,/g, ""));
	    // 체크박스 체크 or 해제 
	    if($(".all_check_input").prop("checked")){
	        $(".cartCheck:not(:disabled)").prop("checked", true);
	        $(".cartCheck:not(:disabled)").each(function() {
	            let total = parseInt($(this).val().replace(/,/g, ""));
	            total_val += total;
	        });
	        
	    } else{
	        $(".cartCheck:not(:disabled)").prop("checked", false);
	        let total = 0;
	        total_val = 0;
	    }
	    $(".total_val").val(total_val.toLocaleString('ko-KR'));
	});
	
	//체크박스 설정
	$(".cartCheck").on("click", function() {
	    let total_val = parseInt($(".total_val").val().replace(/,/g, "")); // 기존 total_val 값, 기존에 '3,005 이런식으로 , 가 있기에 공백으로 변환'
	    let total = parseInt($(this).val().replace(/,/g, ""));
	    if ($(this).is(":checked")) { //($(this) ==> 체크박스 value, checked 즉 ckeckbox가 체크되어 있는 상태)	
	        total_val += total;
	    } else {
	        total_val -= total;
	        total = 0;
	    }
	    $(".total_val").val(total_val.toLocaleString('ko-KR'));
	 	// 모든 체크박스가 선택되어 있는지 확인
	    let allChecked = true;
	    $(".cartCheck").each(function() {
	        if (!$(this).is(":checked")) { // 한 개라도 체크되지 않은 체크박스가 있다면
	            allChecked = false; // allChecked를 false로 설정
	        }
	    });
	 	// 모든 체크박스가 선택되어 있지 않다면 전체 체크박스의 체크를 해제
	    if (!allChecked) {
	        $(".all_check_input").prop("checked", false);
	    } else {
	    	$(".all_check_input").prop("checked", true);
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
		<!------ 컨텐츠 내용 ------>
		<div class="board-top">
		<div class="a-table-view02">
		<!-- 장바구니 list 비었는지 확인 -->
		<c:if test="${list != null && list.size() < 1}">
			<div style="margin-top: 30px;">
				<div><strong>장바구니에 담긴 상품이 없습니다.</strong></div>
				<div><em>원하는 상품을 장바구니에 담아보세요!</em></div>
				<div><a href="/keycap/list?sort=null" class="list-btn">쇼핑 계속하기 ></a></div>
			</div>
		</c:if>
		<c:if test="${list != null && list.size() >= 1}">
		<!-- submit 하면 form 값을 @GM("/orders")로 보냄 -->
		<form name="cartOrders" method="get" action="/cart/ordersCart" >
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
			<col style="width:7%">
			<col style="width:5%">
			<col style="width:45%">
			<col style="width:7%">
			<col style="width:7%">
			<col style="width:14%">
			<col style="width:15%">
		</colgroup>
		<thead>
			<tr>
				<th scope="col">전체 ${totalCart}개</th>
				<th scope="col" class="all_check_input_div"><input type="checkbox" class="all_check_input" checked="checked"></th>
				<th scope="col">상품명</th>
				<th scope="col">판매가</th>
				<th scope="col">수량</th>
				<th scope="col">주문관리</th>
				<th scope="col">배송비/배송형태</th>
			</tr>
		</thead>
		<tbody>
		<c:set var="count" value="0" /> <!-- 카운트를 위한 변수 설정(forEach 밖에서 선언함으로서 항상 count가 0으로 초기화되는것을 막음) -->
		
		<c:forEach var="item" items="${list}">
		<c:forEach var="keycap" items="${item.keycap}"> <!-- cart.xml에 있는 keycap에 접근할 수 있다....CartMap -->
		
		<c:set var="price" value="${keycap.keycapPrice}"/> <!-- item.price는 상품 가격 -->
		<c:set var="quantity" value="${item.cartCount}"/> <!-- item.quantity는 상품 수량 -->
		<c:set var="total" value="${price * quantity}" /> <!-- 각각의 상품금액 -->
		
		<tr class="mypage-trHover">
		<td><c:set var="count" value="${count + 1}" />${count}
			<input id="cartNum" type="hidden" name="cartNum" value="${item.cartNum}">
		</td>
		<td>
			<c:if test="${keycap.keycapStock < 1 && list.size() >= 1}">
				<input class="cartCheck" type="checkbox" name="cartCheck" value="0" disabled>
			</c:if>
			<c:if test="${keycap.keycapStock >= 1 && list.size() >= 1}">
				<input class="cartCheck" type="checkbox" name="cartCheck" value="${total}" checked>
			</c:if>
		</td>
		<td>
			<div class="announcemen-box">
				<a href="/keycap/${item.keycapNum}/keycapView" class="img-block">
					<img src="/HwicapUpload/${keycap.keycapImg}">
					<input id="orderImg" type="hidden" name="orderImg" value="${keycap.keycapImg}">
				</a>
				<ul class="info">
					<li class="name">
						<a href="/keycap/${item.keycapNum}/keycapView">${keycap.keycapName}</a>
						<input id="keycapName" type="hidden" name="keycapName" value="${keycap.keycapName}">
					</li>
					<c:if test="${keycap.keycapStock >= 5 && list.size() >= 1}">
						<li class="category">재고 5개 이상</li>
					</c:if>
					<c:if test="${keycap.keycapStock >= 1 && list.size() >= 1 && keycap.keycapStock < 5}">
						<li class="category">재고 ${keycap.keycapStock}개 남음</li>
					</c:if>
					<c:if test="${keycap.keycapStock < 1 && list.size() >= 1}">
						<li class="category">품절</li>
					</c:if>
				</ul>
			</div>
		</td>
		<td><fmt:formatNumber value="${total}" pattern="#,###" />원
			<input id="total" class="total" type="hidden" name="total" value="${total}">
			<c:set var="total_val" value="${total_val + total}" />
		</td>
		<td>
			${item.cartCount}개
			<input id="cartCount" type="hidden" name="cartCount" value="${item.cartCount}">
		</td>
		<td>
			<a href="/cart/${item.cartNum}/delete" class="mypage-btn-review" style="cursor:pointer;">삭제하기</a>
		</td>
		<td>
			<div>택배배송</div>
			<div style="font-size: 600; color: #333;">배송비무료</div>
			<diV>0원 이상 무료</diV>
		</td>		
		</tr>	
		</c:forEach>
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
			<button onclick="submit(event)" id="order-btn"><output class="total_val"><fmt:formatNumber value="${total_val}" pattern="#,###"/></output>원 결제하기</button>
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