<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<jsp:include page="head.jsp"></jsp:include>	
<script>
//jQuery는 DOM(Document Object Model)이 준비된 후에 실행되기 때문에, 이를 이용하면 페이지 로딩 완료 후 바로 해당 코드를 실행함.
$(document).ready(function() {
	//리뷰 수 가 존재 한다면 display: block; 처리
	var reviewCounts1 = [];
    <c:forEach var="item" items="${keycap}" varStatus="status">
    	reviewCounts1[<c:out value="${status.index}"/>] = <c:out value="${reviewTotals[item.keycapNum]}" default="0"/>;
    </c:forEach>

    var reviewCounts2 = [];
    <c:forEach var="item" items="${keycapBest}" varStatus="status">
        reviewCounts2[<c:out value="${status.index}"/>] = <c:out value="${reviewTotalsBest[item.keycapNum]}" default="0"/>;
    </c:forEach>
    
    var reviewCounts3 = [];
    <c:forEach var="item" items="${keycapReviewDesc}" varStatus="status">
        reviewCounts3[<c:out value="${status.index}"/>] = <c:out value="${reviewTotalsBest[item.keycapNum]}" default="0"/>;
    </c:forEach>

    for (var i = 0; i < reviewCounts1.length; i++) {
        if (reviewCounts1[i] >= 1) {  // 리뷰 수가 1 이상이면
            var element = $('#reviewInfo1' + i);  // ID로 요소를 선택
            if (element) {
                element.show();  // 요소를 보이게 함
            }
        }
    }
    
    for (var i = 0; i < reviewCounts2.length; i++) {
        if (reviewCounts2[i] >= 1) {  // 리뷰 수가 1 이상이면
            var element = $('#reviewInfo2' + i);  // ID로 요소를 선택
            if (element) {
                element.show();  // 요소를 보이게 함
            }
        }
    }
    
    for (var i = 0; i < reviewCounts3.length; i++) {
        if (reviewCounts3[i] >= 1) {  // 리뷰 수가 1 이상이면
            var element = $('#reviewInfo3' + i);  // ID로 요소를 선택
            if (element) {
                element.show();  // 요소를 보이게 함
            }
        }
    }
    
    //메인 페이지 메인이미지 교체
    var images = ['img/main-img1.png', 'img/main-img2.png', 'img/main-img3.png', 'img/main-img4.png'];
    var links = [null, '/keycap/2/keycapView', '/keycap/3/keycapView', '/keycap/4/keycapView'];
    var slideIndex = 0;
    var autoSlideInterval;
	
    //이미지 교체(다음, 이전 버튼, (전역 범위 에서 실행 가능 window.))
    window.changeImage = function(n) {
        stopAutoSlide();
        slideIndex += n;
        if (slideIndex < 0) {slideIndex = images.length - 1}    
        if (slideIndex >= images.length) {slideIndex = 0}
        var imageSlider = document.getElementById('imageSlider');
        imageSlider.src = images[slideIndex];
        if (links[slideIndex] != null) {
            imageSlider.onclick = function() {
                window.location.href = links[slideIndex];
            }
            imageSlider.classList.add('cursor-pointer');
        } else {
            imageSlider.onclick = null;
            imageSlider.classList.remove('cursor-pointer');
        }
        showAndHighlightSlide(slideIndex+1);
        startAutoSlide();
    }
  	//홈페이지 로딩 후 3초 뒤 자동으로 이미지 교체
    function startAutoSlide() {
        autoSlideInterval = setInterval(function() {
            changeImage(1);
        }, 3000);
    }
	//자동 이미지 이동 멈추기
    function stopAutoSlide() {
        clearInterval(autoSlideInterval);
    }
	
    //이미지 src 교체(전역 범위 에서 실행 가능 window.)
    window.currentSlide = function(n) {
	    stopAutoSlide();
	    slideIndex = n - 1;
	    var imageSlider = document.getElementById('imageSlider');
	    imageSlider.src = images[slideIndex];
	    if (links[slideIndex] != null) {
	        imageSlider.onclick = function() {
	            window.location.href = links[slideIndex];
	        }
	        imageSlider.classList.add('cursor-pointer');
	    } else {
	        imageSlider.onclick = null;
	        imageSlider.classList.remove('cursor-pointer');
	    }
	    showAndHighlightSlide(n);
	    startAutoSlide();
	}
	
    //해당하는 이미지의 동그라미 버튼 style 바꾸기
    function showAndHighlightSlide(n) {
        var i;
        var dots = document.getElementsByClassName("dot");
        for (i = 0; i < dots.length; i++) {
            dots[i].style.backgroundColor = "#333";  
            dots[i].style.boxShadow = "0 0 3px #767676";
        }
        dots[n-1].style.backgroundColor = "white";
        dots[n-1].style.boxShadow = "0 0 3px #000";
    } 

    document.getElementById('imageSlider').src = images[slideIndex];
    showAndHighlightSlide(slideIndex+1);
    startAutoSlide();
});
</script>
<meta charset="UTF-8">
</head>
<body>
<div class="wrap">
<header id="header-wrap" style="border-bottom: none;">
<jsp:include page="status-bar.jsp"></jsp:include>	
</header>
		<div class="main-img">
			<img id="imageSlider" src="img/main-img1.png" style="width: 1260px; height: 619px;">
			<!-- jstl 비교연산자를 이용한 다음, 이전 버튼 -->
			<a href="#" class="main-img-btn" style="left: 10%;" onclick="changeImage(-1); return false;"><i class="fas fa-chevron-left"></i></a>
    		<a href="#" class="main-img-btn" style="right: 10%;" onclick="changeImage(1); return false;"><i class="fas fa-chevron-right"></i></a>
    		
    		<!-- 각각의 동그라미 버튼에 onclick 이벤트를 추가하여 해당하는 이미지 호출 -->
			<div class="dot-container">
				<span class="dot" onclick="currentSlide(1)"></span> 
				<span class="dot" onclick="currentSlide(2)"></span> 
				<span class="dot" onclick="currentSlide(3)"></span> 
				<span class="dot" onclick="currentSlide(4)"></span> 
			</div>
		</div>
		
	<div id="main-wrap">
		<div class="announcement-text">
			<strong class="title-s" style="margin-top: 5%;">신상품</strong>
		</div>
		<div class="index-hidden"></div>
	<div class="announcement-index01">
	<div class="announcement-index02">
		<ul class="announcement-indexVeiwPort" style="position: relative; z-index: 2000; overflow: hidden; 
		min-height: 100%; width: 100%; touch-action: pan-y; user-select: none; -webkit-user-drag: none; 
		transform: translate3d(0px, 0px, 0px); display: flex; justify-content: center;">
		<c:if test="${keycap.size() < 1}">
			<li class="announcement-list2">
				<strong>등록 된 상품이 없습니다.</strong>
			</li>
		</c:if>
			<c:forEach var="item" items="${keycap}" varStatus="status">
				<li class="announcement-indexVeiwPort-li">
					<div class="announcement-item-img">
						<a href="keycap/${item.keycapNum}/keycapView">
						<img src="/HwicapUpload/${item.keycapImg}" class="announcement-avatar"></a>
					</div>	
					<div class="announcement-item-s">
						<strong><span class="announcement-item-sp"><fmt:formatNumber value="${item.keycapPrice}" pattern="#,###" />원</span></strong>
					</div>
					<div class="announcement-item-s">
					<a href="keycap/${item.keycapNum}/keycapView">
						<strong><span class="announcement-item-sp">${item.keycapName}</span></strong>
					</a>
					</div>
					<div class="announcement-item-s" id="reviewInfo1${status.index}" style="display: none;">
						<!-- averageStars 맵에서 keycapNum에 해당하는  별점 평균을 가져옴 -->
						<span class="announcement-item-sp">평점 : ${averageStars[item.keycapNum]} | </span>
						<!-- reviewTotals 맵에서 keycapNum에 해당하는 리뷰의 총 수를 가져옴 -->
						<span class="announcement-item-sp">리뷰 수 : ${reviewTotals[item.keycapNum]}</span> 
					</div>
					<div class="announcement-item-s">
					<a href="keycap/list">
						<span class="announcement-item-sp">${item.keycapCategory}</span>
					</a>
					</div>
				</li>
				</c:forEach>
			</ul>
		</div>
		</div>
		
		<!-- 베스트 상품  -->
		<div class="announcement-text">
			<strong class="title-s" style="margin-top: 5%;">베스트 상품</strong>
		</div>
		<div class="index-hidden"></div>
	<div class="announcement-index01">
	<div class="announcement-index02">
	<c:if test="${keycap.size() < 1}">
		<div class="announcement-list2">
			<strong>등록 된 상품이 없습니다.</strong>
		</div>
	</c:if>
		<ul class="announcement-indexVeiwPort" style="position: relative; z-index: 2000; overflow: hidden; 
		min-height: 100%; width: 100%; touch-action: pan-y; user-select: none; -webkit-user-drag: none; 
		transform: translate3d(0px, 0px, 0px); display: flex; justify-content: center;">
			<c:forEach var="item" items="${keycapBest}" varStatus="status">
			    <li class="announcement-indexVeiwPort-li">
			    	<div class="announcement-item-img">
				        <a href="keycap/${item.keycapNum}/keycapView">
				        <img src="/HwicapUpload/${item.keycapImg}" class="announcement-avatar" ></a>
					</div>			
			        <div class="announcement-item-s">
			        	<strong><span class="announcement-item-sp"><fmt:formatNumber value="${item.keycapPrice}" pattern="#,###" />원</span></strong>
			        </div>
			        <div class="announcement-item-s">
			            <a href="keycap/${item.keycapNum}/keycapView">
			                <strong><span class="announcement-item-sp">${item.keycapName}</span></strong>
			            </a>
			        </div>
			        <div class="announcement-item-s" id="reviewInfo2${status.index}" style="display: none;">
			            <!-- averageStars 맵에서 keycapNum에 해당하는 별점 평균을 가져옴 -->
			            <span class="announcement-item-sp">평점 : ${averageStarsBest[item.keycapNum]} | </span>
			            <!-- reviewTotals 맵에서 keycapNum에 해당하는 리뷰의 총 수를 가져옴 -->
			            <span class="announcement-item-sp">리뷰 수 : ${reviewTotalsBest[item.keycapNum]}</span>
			        </div>
			        <div class="announcement-item-s">
			            <a href="keycap/list">
			                <span class="announcement-item-sp">${item.keycapCategory}</span>
			            </a>
			        </div>
			    </li>
			</c:forEach>
		</ul>
		</div>
		</div>	
		
		<!-- 리뷰많은 상품  -->
		<div class="announcement-text">
			<strong class="title-s" style="margin-top: 5%;">리뷰많은 상품</strong>
		</div>
		<div class="index-hidden"></div>
	<div class="announcement-index01">
	<div class="announcement-index02">
	<c:if test="${keycap.size() < 1}">
		<div class="announcement-list2">
			<strong>등록 된 상품이 없습니다.</strong>
		</div>
	</c:if>
		<ul class="announcement-indexVeiwPort" style="position: relative; z-index: 2000; overflow: hidden; 
		min-height: 100%; width: 100%; touch-action: pan-y; user-select: none; -webkit-user-drag: none; 
		transform: translate3d(0px, 0px, 0px); display: flex; justify-content: center;">
			<c:forEach var="item" items="${keycapReviewDesc}" varStatus="status">
			    <li class="announcement-indexVeiwPort-li">
			    	<div class="announcement-item-img">
				        <a href="keycap/${item.keycapNum}/keycapView">
				        <img src="/HwicapUpload/${item.keycapImg}" class="announcement-avatar" ></a>
					</div>			
			        <div class="announcement-item-s">
			        	<strong><span class="announcement-item-sp"><fmt:formatNumber value="${item.keycapPrice}" pattern="#,###" />원</span></strong>
			        </div>
			        <div class="announcement-item-s">
			            <a href="keycap/${item.keycapNum}/keycapView">
			                <strong><span class="announcement-item-sp">${item.keycapName}</span></strong>
			            </a>
			        </div>
			        <div class="announcement-item-s" id="reviewInfo3${status.index}" style="display: none;">
			            <!-- averageStars 맵에서 keycapNum에 해당하는 별점 평균을 가져옴 -->
			            <span class="announcement-item-sp">평점 : ${averageStarsBest[item.keycapNum]} | </span>
			            <!-- reviewTotals 맵에서 keycapNum에 해당하는 리뷰의 총 수를 가져옴 -->
			            <span class="announcement-item-sp">리뷰 수 : ${reviewTotalsBest[item.keycapNum]}</span>
			        </div>
			        <div class="announcement-item-s">
			            <a href="keycap/list">
			            	<span class="announcement-item-sp">${item.keycapCategory}</span>
			            </a>
			        </div>
			    </li>
			</c:forEach>
		</ul>
		</div>
		</div>
	<div class="procedure" style="margin-top: 5%;">
		<img src="img/main-bottom.png" style="max-width: 1260px;">
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