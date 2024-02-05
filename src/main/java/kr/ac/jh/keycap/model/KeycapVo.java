package kr.ac.jh.keycap.model;

import java.util.Date;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class KeycapVo {
	
	int keycapNum;
	Date keycapRegDate;
	String keycapName;
	String keycapId;
	int keycapStock;
	int keycapReadCount;
	int keycapLike;
	String keycapImg;
	String keycapContent;
	int keycapPrice;
	String keycapCategory;
	int keycapOrder;
	
	MultipartFile uploadFile; 
	
	String adminId;
	List<ReviewVo> review;
	List<BoardVo> board;
	
	public int getKeycapNum() {
		return keycapNum;
	}
	public void setKeycapNum(int keycapNum) {
		this.keycapNum = keycapNum;
	}
	public Date getKeycapRegDate() {
		return keycapRegDate;
	}
	public void setKeycapRegDate(Date keycapRegDate) {
		this.keycapRegDate = keycapRegDate;
	}
	public String getKeycapName() {
		return keycapName;
	}
	public void setKeycapName(String keycapName) {
		this.keycapName = keycapName;
	}
	public String getKeycapId() {
		return keycapId;
	}
	public void setKeycapId(String keycapId) {
		this.keycapId = keycapId;
	}
	public int getKeycapStock() {
		return keycapStock;
	}
	public void setKeycapStock(int keycapStock) {
		this.keycapStock = keycapStock;
	}
	public int getKeycapReadCount() {
		return keycapReadCount;
	}
	public void setKeycapReadCount(int keycapReadCount) {
		this.keycapReadCount = keycapReadCount;
	}
	public int getKeycapLike() {
		return keycapLike;
	}
	public void setKeycapLike(int keycapLike) {
		this.keycapLike = keycapLike;
	}
	public MultipartFile getUploadFile() {
		return uploadFile;
	}
	public void setUploadFile(MultipartFile uploadFile) {
		this.uploadFile = uploadFile;
	}
	public String getAdminId() {
		return adminId;
	}
	public void setAdminId(String adminId) {
		this.adminId = adminId;
	}
	public String getKeycapImg() {
		return keycapImg;
	}
	public void setKeycapImg(String keycapImg) {
		this.keycapImg = keycapImg;
	}
	public int getKeycapPrice() {
		return keycapPrice;
	}
	public void setKeycapPrice(int keycapPrice) {
		this.keycapPrice = keycapPrice;
	}
	public String getKeycapCategory() {
		return keycapCategory;
	}
	public void setKeycapCategory(String keycapCategory) {
		this.keycapCategory = keycapCategory;
	}
	public int getKeycapOrder() {
		return keycapOrder;
	}
	public void setKeycapOrder(int keycapOrder) {
		this.keycapOrder = keycapOrder;
	}
	public List<ReviewVo> getReview() {
		return review;
	}
	public void setReview(List<ReviewVo> review) {
		this.review = review;
	}
	public List<BoardVo> getBoard() {
		return board;
	}
	public void setBoard(List<BoardVo> board) {
		this.board = board;
	}
	public String getKeycapContent() {
		return keycapContent;
	}
	public void setKeycapContent(String keycapContent) {
		this.keycapContent = keycapContent;
	}
	
}
