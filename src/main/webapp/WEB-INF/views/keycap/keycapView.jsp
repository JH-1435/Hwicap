<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<c:set var="contextPath" value="${pageContext.request.contextPath}"  />
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<jsp:include page="../head.jsp"></jsp:include>
<script type="text/javascript">	
	//수량 버튼 조작 or 수량 임의 조작
	$(function() {
	var quantity = $(".quantityInput").val();
	let stock = <c:out value="${item.keycapStock}"/>;
	let price = <c:out value="${item.keycapPrice}"/>;
	let total = 0;
	$(".quantityInput").keyup(function(){
		quantity = $(".quantityInput").val();
        total = (price * Math.floor(quantity)).toLocaleString('ko-KR');
        
        if(stock < quantity)
        {
        	quantity = stock;
        	
        	total = (stock * price).toLocaleString('ko-KR');
        }
        else if(quantity == "." || quantity <= 1)
        {
        	quantity = 1;
        	total = price.toLocaleString('ko-KR');
        }
        
        $(".quantityInput").val(Math.floor(quantity));
		$(".quantityTotal").val(total.toLocaleString('ko-KR'));
    });
	$(".plusBtn").on("click", function(){
		if(stock > quantity)
			{
				$(".quantityInput").val(++quantity);
				total = price * quantity;
				$(".quantityTotal").val(total.toLocaleString('ko-KR'));
			}
		else {
			return;
		}
	});
	$(".minusBtn").on("click", function(){
		if(quantity > 1){
			$(".quantityInput").val(--quantity);
			total = price * quantity;
			$(".quantityTotal").val(total.toLocaleString('ko-KR'));
		}
	});
	});
	
	//장바구니 담기 (data : {keycapNum : keycapNum, cartCount : cartCount} 즉 이 변수 값을 서버(controller)로 보냄)
	function add_cart(keycapNum) {
		let cartCount = $(".quantityInput").val();
		$.ajax ({
			type : "post",
			async : false,
			url : "/cart/add",
			data : {keycapNum : keycapNum, cartCount : cartCount},
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
					var link = '/cart/${sessionScope.user.userId}/list';
					var result = confirm("장바구니에 상품을 담았습니다. \n장바구니로 이동하시겠습니까?");
					if(result)
				    {
						location.replace(link);
				    }
				    else
				    {
				       return;
				    }
					
				} else if(data.trim()=='already_existed') {
					alert("이미 장바구니에 등록된 제품입니다.");
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
	
	//찜하기 (data : {keycapNum : keycapNum, heartTry : heartTry} 즉 이 변수 값을 서버(controller)로 보냄)
	function add_heart(keycapNum, heartTry) {
		var heartVal = $(".heartVal").val();
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
					$(".far.fa-heart").removeClass("far fa-heart").addClass("fas fa-heart");
					$(".heartVal").val(++heartVal);
					$(".fas.fa-heart").css('color', '#f33');
					$(".heartVal").css('color', '#f33');
					return;
					
				} else if(data.trim()=='already_existed') {
					$(".fas.fa-heart").removeClass("fas fa-heart").addClass("far fa-heart");
					$(".heartVal").val(--heartVal);
					$(".far.fa-heart").css('color', '#000');
					$(".heartVal").css('color', '#000');
					return;
				}
				//onload에서 한 첫 실행(유저가 찜하기 이미 되있다면 하트색과 찜하기 수 를 칠하기 위함)
				else if(data.trim()=='first_try_true') {
					$(".far.fa-heart").removeClass("far fa-heart").addClass("fas fa-heart");
					$(".fas.fa-heart").css('color', '#f33');
					$(".heartVal").css('color', '#f33');
					return;
				} else if(data.trim()=='first_try_false') {
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
	
	//구매하기 (data : {cartCount : cartCount, total : total} 즉 이 변수 값을 서버(controller)로 보냄)
	function add_content(keycapNum) {
		var cartCount = $(".quantityInput").val();
		//url 디코딩 하여 (',' 값 빼기)
		var decodedValue = decodeURIComponent($(".quantityTotal").val());
		var total = decodedValue.replace(',', '');
		$.ajax ({
			type : "get",
			async : false,
			url : "${contextPath}/keycap/content?keycapNum=${item.keycapNum}",
			data : {cartCount : cartCount, total : total},
			success : function(data, textStatus) {				
				var link_1 = '${contextPath}/keycap/content?keycapNum=${item.keycapNum}'
				var link_2 = '&cartCount=' + cartCount;
				var link_3 = '&total=' + total;
				
				var link = link_1 + link_2 + link_3;
				
				location.replace(link);
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
	
	//별점 평균값 구하기
	window.onload = function() {		
	    var averageStar = parseFloat("${averageStar}"); // 별점의 평균값을 서버로부터 받아옵니다.
	    var formattedStar = averageStar.toFixed(1); // 소수점 첫째 자리까지 표시합니다.
	    $(".averageStar").text(formattedStar + "/5"); // 결과를 HTML에 표시합니다.
	    
	    // 별점에 따라 별의 색을 채웁니다.
	    var stars = $("#starRating .fa-star, #starRating .far").get().reverse(); // 별 요소를 가져온 후 순서를 뒤집습니다.
	    var fullStars = Math.floor(averageStar);
	    var halfStar = averageStar % 1 >= 0.5; // 소수점이 0.5 이상인지 확인합니다.

	    for (var i = 0; i < fullStars; i++) {
	        $(stars[i]).removeClass("far fa-star").addClass("fas fa-star"); // 별의 색을 채웁니다.
	    }
	    
	    // 소수점이 0.5 이상인 경우, 반 별 아이콘을 채웁니다.
	    if (halfStar && fullStars < 5) {
	        $(stars[fullStars]).removeClass("far fa-star").addClass("fas fa-star-half-alt"); // 반 별의 색을 채웁니다.
	    }
	}
	
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
		                    imgInBox.style.width = '160px';
		                    imgInBox.style.height = 'auto';
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
		
		//QnA 더보기 기능
		var boardTitles = document.querySelectorAll('.board_title');
			    			
		boardTitles.forEach(function(title) {
		    title.addEventListener('click', function() {
		        var currentElement = this;
		        var boardNum = currentElement.getAttribute('data-boardnum');
		        $.ajax({
		            type: "post",
		            async: false,
		            url: '${contextPath}/keycap/checkBoardUser',
		            data: { boardNum: boardNum },
		            success: function(data, textStatus) {
		                // 게시물 내용과 답변 요소를 직접 선택
		                var content = currentElement.closest('li').querySelector('.board_content');
		                var answer = currentElement.closest('li').querySelector('.boardAnswer');

		                if (data.trim() == 'user_true') {
		                    // 게시물 내용과 답변 요소의 표시 상태를 토글함
		                    if(content) content.style.display = content.style.display === 'none' ? 'table' : 'none';
		                    if(answer) answer.style.display = content.style.display;
		                } else {
		                    alert("문의내역은 작성자 본인만 확인 할 수 있습니다.");
		                }
		            },
		            error: function(data, textStatus) {
		                //alert("에러가 발생했습니다. " + data);
		            },
		            complete: function(data, textStatus) {
		                //console.log(data);
		                //alert("작업을 완료했습니다. " + textStatus);
		            }
		        });
		    });
		});
	    
	 	//초기엔 문의 내용 안보이게 함
	    var boardContents = document.querySelectorAll('.ckeditor_content.board_content');
	    boardContents.forEach(function(content) {
	    content.style.display = 'none';
	    });
		
	  //QnA 답변 or 미답변 표시
		var answerStatuses = document.querySelectorAll('.board-answer');
		answerStatuses.forEach(function(status) {
			var value = status.getAttribute('data-value');
		    if (value === '1') {
		    	status.innerHTML = '<em>답변완료</em>';
		        status.style.color = '#0078ff';
		   	} else {
		        status.textContent = '미답변';
		   }
		});
	});

	// 페이지가 로드되면 '상세정보' 탭을 자동으로 선택, 찜하기 버튼 설정 함.
	window.addEventListener('load', function() { 
		// 탭 키 선택
		var tablinks = document.querySelectorAll(".tablinks");
	    tablinks.forEach(function(tab) {
	        tab.onclick = function() {
	            // 모든 탭의 aria-current 속성을 false로 설정
	            tablinks.forEach(function(innerTab) {
	                innerTab.setAttribute("aria-current", "false");
	            });
	            // 클릭한 탭의 aria-current 속성을 true로 설정
	            this.setAttribute("aria-current", "true");
	
	            // 클릭한 탭의 클래스 이름을 가져옴
	            var tabClass = this.className.split(' ')[1];
	
	            // nav-tab의 동일한 클래스를 가진 요소를 찾음
	            var navTablinks = document.querySelectorAll(".nav-tab ." + tabClass);
	
	            // nav-tab의 모든 탭의 aria-current 속성을 false로 설정
	            navTablinks.forEach(function(navTab) {
	                navTab.setAttribute("aria-current", "false");
	            });
	
	            // nav-tab의 동일한 클래스를 가진 탭의 aria-current 속성을 true로 설정
	            if (navTablinks.length > 0) {
	                navTablinks[0].setAttribute("aria-current", "true");
	            }
	        }
	    });
		  		
		// 처음 찜하기 버튼 클릭 설정
		var userId = '${sessionScope.user.userId}';
		if (userId != "") {
	        add_heart('${item.keycapNum}', 0);
	    }
		
	});
	
	//TAB
	window.addEventListener('scroll', function() {
		// 현재 스크롤 위치를 가져옴
		const scrollPosition = window.pageYOffset || document.documentElement.scrollTop || document.body.scrollTop || 0;

	    // 각 섹션의 위치를 가져옴
	    const detailPosition = document.querySelector('#product-row').offsetTop;
	    const reviewPosition = document.querySelector('#Review').offsetTop;
	    const qnaPosition = document.querySelector('#QnA').offsetTop;
	    const refundPosition = document.querySelector('#refund').offsetTop;

	    // 'tab-table' 클래스를 가진 요소를 선택
	    var tabTableElement = document.querySelector('.tab-table');
	    // 'nav-tab' 클래스를 가진 요소를 선택
	    var navTabElement = document.querySelector('.nav-tab');
	    // 'tab-table' 요소의 상단 위치를 가져옴
	    var tabTablePosition = tabTableElement.getBoundingClientRect().top;

	    // 'tab-table' 요소가 화면상단에 닿았는지 확인
	    if (tabTablePosition <= 0) {
	        // 'tab-table' 요소가 화면상단에 닿았을 때 'nav-tab' 요소를 노출 함
	        navTabElement.style.display = 'block';
	    } else {
	        // 'tab-table' 요소가 화면상단에 닿지 않았을 때 'nav-tab' 요소를 숨김
	        navTabElement.style.display = 'none';
	    }

	    // 모든 탭을 비활성화 함
	    const tabs = document.querySelectorAll('.tab-cell a');
	    for (let i = 0; i < tabs.length; i++) {
	        tabs[i].setAttribute('aria-current', 'false');
	    }

	    // 스크롤 위치에 따라 해당하는 탭을 활성화 함
	    if (scrollPosition < reviewPosition) {
	        document.querySelectorAll('.tab-detail').forEach(tab => tab.setAttribute('aria-current', 'true'));
	    } else if (scrollPosition < qnaPosition) {
	        document.querySelectorAll('.tab-review').forEach(tab => tab.setAttribute('aria-current', 'true'));
	    } else if (scrollPosition < refundPosition) {
	        document.querySelectorAll('.tab-qna').forEach(tab => tab.setAttribute('aria-current', 'true'));
	    } else {
	        document.querySelectorAll('.tab-refund').forEach(tab => tab.setAttribute('aria-current', 'true'));
	    }
	});
</script>
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<div id="container-wrap">
	<div class="contents" style="width: 1020px; margin: 50px auto 0;">
			<div class="product-details">
				<div class="product-left">
			        <div class="product-photo">
			        <div style="position: absolute; top: 0; left: 0; z-index: 1; background-color: var(--color-picker, #ffffff);"></div>
			            <div class="product-photo-img">
			            	<img src="/HwicapUpload/${item.keycapImg}" id="photo-img"
			                     alt="${item.keycapImg}">
			            </div>
			        </div>
			        <div class="product-content" style="float: left; font-size: 14px;">
						<span>리뷰 수 <strong style="font-size: 20px;">${reviewTotal}</strong></span>		
						<span>| 사용자 총 평점 <strong class="averageStar" style="font-size: 20px;">0/5</strong></span>
						<c:if test="${listReview != null && listReview.size() < 1}">
							<p style="margin-top: 1px; font-size: 12px; line-height: 18px; text-align: left;">아직 작성된 리뷰가 없습니다.</p>
						</c:if>	
					</div>
			    </div>
			    <div class="product-right">
			    	<fieldset style="min-width: 100%;">
				    	<legend class="blind">상품 상세 구매</legend>
				    	<div style="margin-bottom: 12px; min-height: 55px;">
				    		<div style="line-height: 28px;"><h3 id="product-name">${item.keycapName}</h3></div>
				    		<div style="float: right;">
				    			<strong id="product-price"><fmt:formatNumber value="${item.keycapPrice}" pattern="#,###" />원</strong>
				    		</div>
				    	</div>
				    	<div style="padding: 20px 0; border-top: 1px solid #ededed; border-bottom: 1px solid #ededed; font-size: 13px;">
					    	<div style="padding-left: 1px; color: #333333; line-height: 20px;">
					    		<h3 id="product-name">Delivery Info</h3>
					    		<span style="color: #666666;">배송정보</span>
					    	</div>
					    	<div style="margin-top: 15px;">
						    	<div style="display: flex; justify-content: space-between;">
							    	<span>출고 정보</span>
							    	<strong style="padding-right: 46%;">결제 3일 이내 출고</strong>
						    	</div>
						    	<div style="display: flex; justify-content: space-between;">
							    	<span>배송 정보</span>
								    <strong style="padding-right: 42%;">무료배송 | TEST 택배</strong>
							    </div>
					    	</div>
				    	</div>
				    	<c:if test="${item.keycapStock >= 1}">
				    		<div style="margin:20px 0;">
				 				<span style="position: relative; font-size: 14px; margin-right: 5px;">구매수량</span>
								<span>
									<button class="minusBtn" style="height: 28px; width: 34px;"> - </button>
									<input type="text" class="quantityInput" style="height: 27.5px; width: 68px; margin: 0 -5px;" oninput="this.value = this.value.replace(/[^0-9.]/g, '').replace(/(\..*)\./g, '$1');" value="1">
									<button class="plusBtn" style="height: 28px; width: 34px;"> + </button>
								</span>
				    		</div>
				    	</c:if>
				    	<c:if test="${item.keycapStock >= 1}">
				    		<div style="font-size: 13px; line-height: 23px;">
								<strong style="line-height: 16px;">총 상품 금액</strong>
								<div style="float: right;">
									<em id="product-total">총 수량 <output class="quantityInput">1</output>개 | </em>
									<strong id="product-total-blue"><output class="quantityTotal" style="font-size: 24px;"><fmt:formatNumber value="${item.keycapPrice}" pattern="#,###" /></output>원</strong>
								</div>
							</div>
						</c:if>
						<c:if test="${item.keycapStock == 0}">
							<div class="product-row" style="margin-top: 100px">
						    	<div class="product-data">해당 상품이 <strong style="font-size: 20px;">품 절</strong> 되었습니다.</div>
							</div>
						</c:if>
				    	<div style="margin: 0 -2px -2px -2px; padding-top: 16px;">
							<c:if test="${sessionScope.admin == null}">
								<c:if test="${item.keycapStock >= 1}">
									<div style="display: table; table-layout: fixed; width: 100%; height: 100%">
										<div style="display: table-cell; padding: 2px; vertical-align: top; text-align: center; vertical-align: middle; height: 100%;">
											<a id="product-add-btn" href="javascript:add_content('${item.keycapNum}')">
												<span class="product-btn-font">구매하기</span>
											</a>
										</div>
									</div>
								</c:if>
								<div style="display: table; table-layout: fixed; width: 100%;">
									<!-- 찜하기 버튼 -->
									<div style="display: table-cell; padding: 2px; vertical-align: top;">
										<a id="product-cell-btn" href="javascript:add_heart('${item.keycapNum}', 1)">
											<i class="far fa-heart" style="color: #000; padding-right: 5px;"></i>
											<span style="padding-right: 5px;">찜하기</span>
											<output class="heartVal"><fmt:formatNumber value="${item.keycapLike}" pattern="#,###"/></output>
										</a>
									</div>
									<c:if test="${item.keycapStock >= 1}">
									<div style="display: table-cell; padding: 2px; vertical-align: top;">
										<a id="product-cell-btn" href="javascript:add_cart('${item.keycapNum}')">
											<i class="fas fa-shopping-bag" style="padding-right: 5px;"></i>
											<span>장바구니</span>
										</a>
									</div>
									</c:if>
								</div>
							</c:if>
				    	</div>
			    	</fieldset>
				</div>				 
			</div>
			<!-- TAB -->
			<div id="tab" class="tab">
				<ul class="tab-table" role="menubar">
					<li class="tab-cell" role="presentation"><a href="#product-row" class="tablinks tab-detail" role="menuitem" aria-current="true">상세정보</a></li>
					<li class="tab-cell" role="presentation"><a href="#Review" class="tablinks tab-review" role="menuitem" aria-current="false">상품후기</a></li>
					<li class="tab-cell" role="presentation"><a href="#QnA" class="tablinks tab-qna" role="menuitem" aria-current="false">상품문의</a></li>
					<li class="tab-cell" role="presentation"><a href="#refund" class="tablinks tab-refund" role="menuitem" aria-current="false">교환/반품/배송</a></li>
				</ul>
			</div>
			<div class="nav-tab" style="display: none;">
				<div style="position: relative; width: 1020px; margin: 0 auto;">
					<div class="tab" style="position: relative; border-bottom: 0; margin-bottom: 0;">
						<ul class="tab-table" role="menubar">
							<li class="tab-cell" role="presentation"><a href="#product-row" class="tablinks tab-detail" role="menuitem" aria-current="true">상세정보</a></li>
							<li class="tab-cell" role="presentation"><a href="#Review" class="tablinks tab-review" role="menuitem" aria-current="false">상품후기</a></li>
							<li class="tab-cell" role="presentation"><a href="#QnA" class="tablinks tab-qna" role="menuitem" aria-current="false">상품문의</a></li>
							<li class="tab-cell" role="presentation"><a href="#refund" class="tablinks tab-refund" role="menuitem" aria-current="false">교환/반품/배송</a></li>
						</ul>
					</div>
				</div>
			</div>
			<!-- 상품 상세정보 -->
			<div style="margin-top: 100px;"></div>
			<div id="product-row" class="product-row">
			  	<div class="product-data av-1">${item.keycapContent}</div>
			</div>
			    <c:if test="${sessionScope.admin.adminState == 1 }">
			        <div class="btn-group" style="float: none; margin-top: 30px;">
						<a href="/keycap/${item.keycapNum}/update" class="admin-btn"><i class="fas fa-file-signature"></i>수정</a>
						<a href="/keycap/${item.keycapNum}/delete" class="admin-btn"><i class="far fa-trash-alt"></i>삭제</a>		
					</div>
			    </c:if>
		<div class="overflow-hidden">
		
	<c:if test="${item.keycapStock == 0}">
		<div>
			<strong>이 상품은 현재 구매하실 수 없는 상품입니다.</strong>
			<p>(재입고 시 구매가능)</p>
		</div>
	</c:if>
	<div style="margin-top: 100px;"></div>
	<!---- 상품 리뷰내역 ---->
	<div id="Review">
	<div class="mypage-header tabcontent" style="text-align: left;">
		<h4 class="content-h4" style="margin-bottom: 15px;">구매후기</h4>
		<p style="margin-bottom: 15px; line-height: 20px; color: #888;">상품을 구매하신 분들이 작성하신 후기입니다.</p>
	</div>
	<c:if test="${listReview != null && listReview.size() >= 1}">
	<div style="display: table; table-layout: fixed; width: 100%; padding: 35px 0 29px 32px; background-color: #f8f9fb; -webkit-box-sizing: border-box; box-sizing: border-box; text-align: center;">
		<div style="display: table-cell;">	    
		    <strong class="review-card">사용자 총 평점</strong>
		    <div class="rating-container-review rating-container" style="margin-top: 15px;">
		        <ul id="starRating" class="rating" style="font-size: 24px;">
		            <c:forEach var="i" begin="1" end="5">
		                <li><i class="far fa-star"></i></li> <!-- 기본적으로 별이 빈 상태로 시작(far fa-star는 폰트어썸 에서 제공하는 class) -->
		            </c:forEach>
		        </ul>
		    </div>
		    <div class="averageStar" style="font-size: 24px;">
		    	<span>0</span>
		    	<span>/5</span>
		    </div>
	    </div>
	    <div style="display: table-cell;">
			<strong class="review-card">전체 리뷰 수</strong>
			<div style="margin-top: 15px;">
				<i class="far fa-comment" style="font-size: 48px; color: #3d3d4f;"></i> 
			</div>
			<div style="font-size: 24px;">
				<span>${reviewTotal}</span>
			</div>
		</div>
	</div>
	<div style="margin-top: 20px; margin-bottom: 30px; border-bottom: 1px solid #777;"></div>
	<div class="board-view02">
		<ul style="border-bottom: 1px solid #eaeced; padding-left: 0;">
		<c:forEach var="list" items="${listReview}">
			<li style="position: relative;">
				<div style="display: table; position: relative; width: 100%; padding: 20px 0; table-layout: fixed;">
				<div style="position: relative;">
					<div style="width: 200px; height: 50px; text-align: left;">
						<div class="rating-container-review rating-container" style="justify-content: left;">
						    <ul class="rating">
						        <c:forEach var="i" begin="1" end="5">
							            <c:choose>
									        <c:when test="${i > 5 - list.reviewStar}">
									            <li><i class="fa fa-star"></i></li>
									        </c:when>
									        <c:otherwise>
									            <li><i class="far fa-star"></i></li>
									        </c:otherwise>
									    </c:choose>
						        </c:forEach>
						    </ul>
						    <div><strong> ${list.reviewStar}</strong></div>
						</div>
					<div><p>${userNames[list.userId]} | <fmt:formatDate value="${list.reviewDate}" pattern="yyyy-MM-dd"/></p></div>
					</div>
				</div>    
			    <div class="ckeditor_content keycapView-reviewContent" style="cursor: pointer;">
			    	<div class="p-reviewContent" style="width: 1020px; height: auto; white-space: normal; overflow: hidden;">
			    	${list.reviewContent}
			    	</div>
			    	<div class="more" style="display: none; color: #aaa;">...더보기</div>
   					<div class="less" style="display: none; color: #aaa;">...접기</div>
			        <c:if test="${list.reviewImg != null}">
		                <c:set var="imgUrls" value="${fn:split(list.reviewImg, ';')}" />
		                <c:forEach varStatus="status" var="imgUrl" items="${imgUrls}">
		                    <div class="photo-box firstImage" style="${status.index == 0 ? '' : 'display: none;'}"> <!-- 처음 이미지를 모두 none으로 바꾸고 js에서 설정함 -->
		                        <div class="photo-big">
		                            <ul class="announcement-list" style="width: 160px; height: auto;">
		                                <li style="width: 100%;">
		                                    <img src="${imgUrl}" class="announcement-review">
		                                </li>
		                            </ul>
		                        </div>
		                    </div>
		                </c:forEach>
		            </c:if>
		         </div>
			  </div>
			</li>
		</c:forEach>
		</ul>
	</div>
	</c:if>
	<!-- 리뷰 내역 list 비었는지 확인 -->
	<c:if test="${listReview != null && listReview.size() < 1}">
	<div style="margin-top: 100px"></div>
		<div>
			<div><strong>등록된 후기가 없습니다.</strong></div>
			<div><em>상품을 구매하여 첫 후기를 등록 해보세요!</em></div>
		</div>
	</c:if>
	<!-- 리뷰 내역 page-nation -->
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
	</div>
	<div style="margin-top: 100px;"></div>
	<!---- 상품 문의내역 ---->
	<div id="QnA">
	<div class="mypage-header tabcontent" style="text-align: left;">
	<h4 class="content-h4" style="margin-bottom: 15px;">상품문의</h4>
		<p style="margin-bottom: 15px; line-height: 20px; color: #888;">구매하시려는 상품에 대해 궁금한 점이 있으신 경우 문의해주세요.</p>
		<c:if test="${sessionScope.admin == null}">
		<div>
			<a id="qna-add-btn" href="/board/${item.keycapNum}/add">상품문의 작성하기</a>		
			<c:if test="${sessionScope.user == null}">
            	<a id="qna-list-btn" href="/login">나의 문의내역 조회 ></a>
            </c:if>
            <c:if test="${sessionScope.user != null}">
            	<a id="qna-list-btn" href="/board/${sessionScope.user.userId}/list">나의 문의내역 조회 ></a>
            </c:if>
		</div>		
		</c:if>
	</div>
	  <c:if test="${listBoard != null && listBoard.size() >= 1}">
	  <div>
	  	<ul class="flex-table" style="margin: 0 auto;">
	  		<li class="qnaTable-cell" style="width: 92px; padding-right: 24px; -webkit-box-sizing: border-box; box-sizing: border-box; padding-inline-start: 0;"><span class="qnaTable-cell-font">답변상태</span></li>
	  		<li class="qnaTable-cell"><span class="qnaTable-cell-font">제목</span></li>
	  		<li class="qnaTable-cell" style="width: 88px;"><span class="qnaTable-cell-font">작성자</span></li>
	  		<li class="qnaTable-cell" style="width: 99px;"><span class="qnaTable-cell-font">작성일</span></li>
	  	</ul>
	  	<ul style="border: solid #dadada; border-width: 1px 0; margin: 0 auto; padding-inline-start: 0;">
		<c:forEach var="listBoard" items="${listBoard}">
			<li id="board-list" class="board-view02">
			<div class="flex-table" style="padding-left: 40px;">
				<div class="qnaTable-cell" style="width: 92px; padding-right: 24px; -webkit-box-sizing: border-box; box-sizing: border-box;"><p class="board-answer" data-value='${listBoard.boardYn}'></p></div>
				<div class="board_title qnaTable-cell" data-boardnum="${listBoard.boardNum}" style="text-align: left;"> 
					<i class="fas fa-lock" style="color:#5f5f5f;"></i><span style="cursor:pointer; color:#5f5f5f;"> ${listBoard.boardTitle}</span>
				</div>
				<div class="qnaTable-cell" style="width: 88px;"><span>${userNames[listBoard.userId]}</span></div>
				<div class="qnaTable-cell" style="width: 99px;"><fmt:formatDate value="${listBoard.boardDate}" pattern="yyyy-MM-dd"/></div>
			</div>
			<div style="padding-inline-start: 0;"></div>
			<div style="padding-left: 131px; border-top: 1px solid #eaeced; background-color: #f7f8fa;">
				<div class="ckeditor_content board_content" style="display: none; padding: 16px 187px 19px 0; word-break: break-all; text-align: left; font-size: 14px; cursor: pointer;">
			        ${listBoard.boardContent}
			        <c:if test="${listBoard.boardImg != null}">
		                <c:set var="imgUrls" value="${fn:split(listBoard.boardImg, ';')}" />
		                <c:forEach varStatus="status" var="imgUrl" items="${imgUrls}">
		                    <div class="photo-box firstImage" style="${status.index == 0 ? '' : 'display: none;'}"> <!-- 처음 이미지를 모두 none으로 바꾸고 js에서 설정함 -->
		                        <div class="photo-big">
		                            <ul class="announcement-list">
		                                <li style="width: 100%;">
		                                    <img src="${imgUrl}" class="announcement-review" style="width: 160px; height: auto;">
		                                </li>
		                            </ul>
		                        </div>
		                    </div>
		                </c:forEach>
		            </c:if>
			    </div>
			    <!-- 답변 -->
		        <c:if test="${listBoard.boardYn == 1}">
			    	<div class="boardAnswer" style="display:none; width: 100%; border-top: 1px solid #eaeced; table-layout: fixed;">
				    	<div style="position: relative; display: table-cell; padding: 16px 0; word-break: break-all; text-align: left; font-size: 14px;">${listBoard.boardAnswer}</div>
				    	<div class="qnaTable-cell" style="width: 88px;">휘캡 담당자</div>
				    	<div class="qnaTable-cell" style="width: 99px;">&nbsp;</div>
				    </div>
			   	</c:if>
			</div>
			</li>
		</c:forEach>
		</ul>
		</div>
	</c:if>
	<!-- QnA 내역 list 비었는지 확인 -->
	<c:if test="${listBoard != null && listBoard.size() < 1}">
	<div style="margin-top: 100px"></div>
		<div>
			<div><strong>등록된 문의글이 없습니다.</strong></div>
			<em>구매하시려는 상품에 대해 궁금한 점이 있으신 경우 문의해주세요.</em>
		</div>
	</c:if>
	<!-- QnA 내역 page-nation -->
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
	<div style="margin-top: 100px;"></div>
	<!-- 교환/반품/배송 -->
	<div id="refund">
	<div class="mypage-header tabcontent" style="text-align: left;">
		<h4 class="content-h4" style="margin-bottom: 15px;">교환/반품/배송</h4>
	</div>
	<div>
	<div>
		<ul style="color: #000; text-align: left; padding-inline-start: 0; font-size: 14px;">
		<li>
			<h4 style="margin: 1.5rem 0 0;">배송지역</h4>
			<div>전국(일부 지역 제외)</div>
			<h4 style="margin: 1.5rem 0 0;">배송비</h4>
			<div>기본배송료는 무료 입니다. (도서,산간,오지 일부지역은 배송비가 추가될 수 있습니다)</div>
			<h4 style="margin: 1.5rem 0 0;">배송기간</h4>
			<div>본 상품의 평균 배송일은 3일입니다. (입금 확인 후) 배송예정일은 주문시점(주문순서)에 따른 유동성이 발생하므로 평균 배송일과는 차이가 발생할 수 있습니다.</div>
			<h4 style="margin: 1.5rem 0 0;">배송가능일</h4>
			<div>본 상품의 배송 가능일은 3일 입니다. 배송 가능일이란 본 상품을 주문 하신 고객님들께 상품 배송이 가능한 기간을 의미합니다.
			<br>(단, 연휴 및 공휴일은 기간 계산시 제외하며 현금 주문일 경우 입금일 기준 입니다.)</div>
		</li>
		<li>
			<h4 style="margin: 1.5rem 0 0;">반품정책</h4>
			<div>
				교환 및 반품은 <span style="color: #333; font-weight: 600;">상품수령 후 7일 이내에 요청</span> 하셔야 하며, <span style="color: #333; font-weight: 600;">사용하지 않은 상품</span>이어야 합니다. 
				단순 변심으로 인한 교환 및 반품 요청시 왕복 또는 편도 배송비는 고객님 부담입니다.
				(택배비 입금처리) 교환 및 반품은 상품 맞교환은 불가능하며, 수령하신 상품이 물류센터로 입고된 후 요청하신 교환상품이 배송됩니다. 
				<span style="color: #333; font-weight: 600;">교환을 원하실 경우, 기존 상품 반품 후 재 주문</span>이 필요합니다. 
				반품에 의한 선환불은 불가능 하며, 반품 상품이 <span style="color: #333; font-weight: 600;">물류센터로 입고된 후 상품의 이상 유무를 확인한 후에 환불처리</span> 해드립니다.
			</div>
			<div>
				<h4 style="margin: 1.5rem 0 0;">교환/반품시 주의사항</h4>
				<ul>
					<li style="list-style: decimal;">교환 및 반품은 <span style="color: #333; font-weight: 600;">제품 수령 후 7일 이내</span>에 가능합니다.</li>
					<li style="list-style: decimal;">상품은 사용한 흔적이 있거나, 상품tag가 손상된 경우 교환/반품/환불이 불가합니다.</li>
					<li style="list-style: decimal;">교환시 맞교환은 불가능하며, 상품 입고 후 교환을 원하시는 제품으로 배송해드립니다.</li>
					<li style="list-style: decimal;">교환 및 반품내역이 접수되지 않거나, 지정된 반송처로 반송되지 않을 시, 교환/반품/환불 절차가 지연되오니 양해 부탁 드립니다.</li>
					<li style="list-style: decimal;">Goods must be returned to our specified address <span style="color: #333; font-weight: 600;">within 7 days</span> after we acknowledge your request.</li>
				</ul>
			</div>
			<div>
				<h4 style="margin: 1.5rem 0 0;">교환/반품시 절차</h4>
				상품 수령후 7일내 1:1 문의 또는 고객센터(042-637-0000)를 통해 신청해주세요.
				<ul>
					<li style="list-style: decimal;">반품 교환시 발생되는 금액은 휘캡 통장으로 입금처리 해주시거나 , 환불금액에서 차감됩니다. 
					<br>(택배비를 동봉하여 분실될 경우 고객님 과실이며, 휘캡에서는 책임지지 않습니다.)</li>
					<li style="list-style: decimal;">지정된 반송처로 반송되지 않을 시, 교환 및 반품 절차가 지연될 수 있습니다.</li>
					<li style="list-style: decimal;">단순 변심으로 인한 교환 및 반품 시 배송비용은 고객님께서 부담하셔야 합니다. (배송착오 및 제품 불량의 경우 제외)
					<br>[반품배송비_편도 3,000원 (최초 배송비 무료인 경우 6,000원 부과), 교환배송비_6,000원]</li>
				</ul>
				<div>반품지 주소: [34503] 대전광역시 동구 우암로 352-21</div>
				<div>고객센터: 042-637-0000</div>
			</div>
			<div>
				<h4 style="margin: 1.5rem 0 0;">교환/반품시 가능한경우</h4>
				<ul>
					<li style="list-style: decimal;">상품을 공급받으신 날로부터 7일 이내에 요청이 가능합니다.</li>
					<li style="list-style: decimal;">상품을 미사용한 상태에서 반송하여 주십시오.</li>
					<li style="list-style: decimal;">반송된 후 물류센터에서 반송확인 후 환불 및 교환처리 됩니다.</li>
				</ul>
			</div>
			<div>
				<h4 style="margin: 1.5rem 0 0;">교환/반품시 불가능한경우</h4>
				<div>다음과 같이 상품이 사용/훼손된 경우에는 교환 및 반품이 되지 않습니다.</div>
				<ul>
					<li style="list-style: decimal;">고객님의 귀책 사유로 상품이 훼손된 경우. (단, 상품의 내용 확인을 위해 포장비닐 등을 훼손한 경우는 제외) </li>
					<li style="list-style: decimal;">상품비닐을 개봉하였거나 훼손되어 상품가치가 현저히 상실된 경우.</li>
					<li style="list-style: decimal;">상품의 TAG, 스티커, 비닐포장, 케이스 등을 훼손 및 분실한 경우.</li>
					<li style="list-style: decimal;">신발 박스의 훼손이 된 경우(신발박스에 직접 테이프 나 송장을 붙이는 경우)</li>
					<li style="list-style: decimal;">시간의 경과에 의하여 재판매가 곤란할 정도로 상품 등의 가치가 현저히 감소한 경우.</li>
				</ul>
			</div>
		</li>
		</ul>		
	</div>
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