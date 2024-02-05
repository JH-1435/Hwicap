<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/fmt" prefix="fmt" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title></title>
</head>
<body>
	<div><h3>주문 상세내역</h3></div>
	<div>
		<table border="1">
			<tbody>
				<tr>
					<td colspan="2">주문번호</td>
					<td colspan="2">${item.orderid}</td>
				</tr>
				<tr>
					<td colspan="2">고객명</td>
					<td colspan="2">${item.name}</td>
				</tr>
				<tr>
					<td colspan="2">금액</td>
					<td colspan="2"><fmt:formatNumber pattern="#,###" value="${item.saleprice}"></fmt:formatNumber></td>
				</tr>
				<tr>
					<td colspan="2">주문일자</td>
					<td colspan="2"><fmt:formatDate pattern="yyyy-MM-dd" value="${item.orderdate}"></fmt:formatDate></td>
				</tr>
				<tr>
					<td colspan="4">주문상세</td>
				</tr>
				<tr>
					<td>상세번호</td>
					<td>도서명</td>
					<td>단가</td>
					<td>수량</td>
				</tr>
				<c:if test="${item.detail.size() < 1}">
				<tr>
					<td colspan="4">주문 내역이 없습니다.</td>
				</tr>
				</c:if>
				<c:forEach var="detail" items="${item.detail}">
				<tr>
					<td>${detail.detailid}</td>
					<td>${detail.bookname}</td>
					<td><fmt:formatNumber value="${detail.price}" pattern="#,###"></fmt:formatNumber></td>
					<td>${detail.amount}</td>
				</tr>
				</c:forEach>
			</tbody>
		</table>
	</div>
	<div><a href="../..">이전</a></div>
</body>
</html>