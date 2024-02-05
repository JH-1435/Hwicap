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
<!-- CKEDITOR_5_keycap.js 를 절대경로 방식으로 불러옴 -->
<script src="/js/CKEDITOR_5_keycap.js"></script>
<script type="text/javascript">	
function submitForm() {
	$('#keycapAddForm').submit();
}

//이미지 파일 체크
function fileCheck(obj) {
	pathPoint = obj.value.lastIndexOf(".");
	filePoint = obj.value.substring(pathPoint+1, obj.length);
	fileType = filePoint.toLowerCase();
	if(fileType == "jpg" || fileType == "gif" || fileType == "png" || 
			fileType == "jpeg" || fileType == "bmp" || fileType == "svg"){
		 previewImage(obj); //function previewImage() 실행
	} else {
		alert("이미지 파일만 선택 가능합니다.");

		//input 파일 초기화
		document.getElementById("file").value = null;
            
            return false;
		}
}

//상품 대표 이미지 미리보기
function previewImage() {
    var preview = document.querySelector('#preview');
    var file    = document.querySelector('#file').files[0];
    var reader  = new FileReader();

    reader.onloadend = function () {
        preview.src = reader.result;
    }

    if (file) {
        reader.readAsDataURL(file);
    } else {
        preview.src = "";
    }
}
</script>
</head>
<body>
<div class="wrap">
<header id="header-wrap">
<jsp:include page="../status-bar.jsp"></jsp:include>
</header>
<div class="left-wrap">
	<h4 class="content-h4" style="line-height: 28px; color: #333;">관리자 메뉴</h4>
	<ul class="admin-list-nav">	
		<c:if test="${sessionScope.admin.adminId == 'admin'}">
			<li><a href="/admin/list">관리자관리</a></li>
		</c:if>
	    <li><a href="/user/list">회원관리</a></li>
		<li><a href="/orders/listAdmin">주문관리</a></li>
		<li><a href="/board/listAdmin">문의관리</a></li>
		<li><a href="/keycap/add" class="on">상품등록</a></li>
		<li><a href="/keycap/list?sort=null">상품관리</a></li>
	</ul>
</div>
<div id="container-wrap">
		<div class="contents">
			<div class="board-top">
			<div class="mypage-header" style="text-align: left;">
				<h4 class="content-h4">상품 등록</h4>
			</div>
				<form id="keycapAddForm" method="post" action="" enctype="multipart/form-data">
				<table class="mypage-table" style="border-top: none;">
				<colgroup>
					<col style="width:14.2%;">
					<col style="width:*;"> 
				</colgroup>
				<thead>
					<tr style="text-align: left; border-bottom: 1px solid #000000;">
						<th style="padding-left: 40px; background: #f7f8f9;">상품 대표 이미지<br>업로드(썸네일)</th>
						<td style="border-bottom: 1px solid #000000; text-align: left;">
						<input style="border: 0; cursor: pointer;" name="uploadFile" type="file" id="file" onchange="fileCheck(this)" 
						accept="image/gif, image/jpg, image/jpeg, image/png, image/svg" />
						<p style="color:red; padding-left: 5px;">파일 크기는 최대 50MB 까지 가능합니다.</p>
						</td>
					</tr>
					<tr style="text-align: left; border-bottom: 1px solid #000000;">
						<th style="padding-left: 40px; background: #f7f8f9;">상품 대표 이미지<br>(썸네일)</th>
						<td style="border-bottom: 1px solid #000000; text-align: left;">
							<div class="board-view02">
							<div class="photo-box">
							<div class="photo-big">
								<ul style="padding: 0;">
									<li>
									<img id="preview" src="/HwicapUpload/" alt="썸네일" class="photo-img" />
									</li>
								</ul>
							</div>
							</div>
							</div>
						</td>
					</tr>
				</thead>
					<!---- 상품 등록 ---->
					<tbody>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">상품 ID</th>
							<td style="border-bottom: 1px solid #000000; text-align: left;">
								<input name="keycapId" type="text" style="width: 400px;">
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
						<th style="padding-left: 40px; background: #f7f8f9;">상품명</th>
							<td style="border-bottom: 1px solid #000000; text-align: left;">
								<input name="keycapName" type="text" style="width: 400px;">
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">카테고리</th>
							<td style="text-align: left; border-bottom: none; width: 100%; padding: 15px;">
							      <input class="boardTitle" type="radio" name="keycapCategory" value="키캡" checked="checked" /><label for="keycap">키캡</label>
							      <input class="boardTitle" type="radio" name="keycapCategory" value="기타" /><label for="etc">기타</label>
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">재고</th>
							<td style="border-bottom: 1px solid #000000; text-align: left;">
								<input name="keycapStock" type="number" style="width: 400px;"> 개
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">가격</th>
							<td style="border-bottom: 1px solid #000000; text-align: left;">
								<input name="keycapPrice" type="number" style="width: 400px;"> 원
							</td>
						</tr>
						<tr style="text-align: left; border-bottom: 1px solid #000000;">
							<th style="padding-left: 40px; background: #f7f8f9;">상세내용</th>
							<td style="border-bottom: none; width: 100%;">
								<textarea rows="200" cols="200" name="keycapContent" id="keycapContent" maxlength="2048"></textarea>
							</td>
						</tr>
					</tbody>
				</table>
				<div class="overflow-hidden">
					<div class="btn-group">
						<input name="adminId" type="hidden" value="${sessionScope.admin.adminId}">
						<a onclick="event.preventDefault(); submitForm();" class="end-btn">상품등록</a>
						<a href="/keycap/list?sort=null" class="end-btn">취소</a>
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