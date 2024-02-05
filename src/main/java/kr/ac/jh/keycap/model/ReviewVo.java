package kr.ac.jh.keycap.model;

import java.util.Date;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class ReviewVo {

	int reviewNum;
	String reviewContent;
	int reviewStar;
	String reviewImg;
	Date reviewDate;
	
	int orderSeqNum;
	String userId;
	int keycapNum;
	
	List<OrdersVo> orders;
	List<KeycapVo> keycap;
	
	MultipartFile uploadFile;

	public int getReviewNum() {
		return reviewNum;
	}

	public void setReviewNum(int reviewNum) {
		this.reviewNum = reviewNum;
	}

	public String getReviewContent() {
		return reviewContent;
	}

	public void setReviewContent(String reviewContent) {
		this.reviewContent = reviewContent;
	}

	public int getReviewStar() {
		return reviewStar;
	}

	public void setReviewStar(int reviewStar) {
		this.reviewStar = reviewStar;
	}
	
	public String getReviewImg() {
		return reviewImg;
	}

	public void setReviewImg(String reviewImg) {
		this.reviewImg = reviewImg;
	}

	public Date getReviewDate() {
		return reviewDate;
	}

	public void setReviewDate(Date reviewDate) {
		this.reviewDate = reviewDate;
	}

	public int getOrderSeqNum() {
		return orderSeqNum;
	}

	public void setOrderSeqNum(int orderSeqNum) {
		this.orderSeqNum = orderSeqNum;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public MultipartFile getUploadFile() {
		return uploadFile;
	}

	public void setUploadFile(MultipartFile uploadFile) {
		this.uploadFile = uploadFile;
	}

	public int getKeycapNum() {
		return keycapNum;
	}

	public void setKeycapNum(int keycapNum) {
		this.keycapNum = keycapNum;
	}

	public List<OrdersVo> getOrders() {
		return orders;
	}

	public void setOrders(List<OrdersVo> orders) {
		this.orders = orders;
	}

	public List<KeycapVo> getKeycap() {
		return keycap;
	}

	public void setKeycap(List<KeycapVo> keycap) {
		this.keycap = keycap;
	}
	
}
