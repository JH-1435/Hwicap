package kr.ac.jh.keycap.model;

import java.util.Date;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

public class OrdersVo {
	int orderSeqNum;
	int keycapNum;
	
	String keycapName;
	
	int orderStock;
	int orderPrice;
	String orderImg;
	String orderUserName;
	String orderTel;
	String orderCall;
	String orderAddress;
	String orderMsg;
	String orderPay;
	String orderCard;
	int orderCardPlan;
	String orderTelPlan;
	String orderState;	
	Date orderPayDate;
	
	
	String userId;
	String userName;
	String userTel;
	String userAddress;
	
	List<KeycapVo> keycap;
	
	MultipartFile uploadFile;

	public int getOrderSeqNum() {
		return orderSeqNum;
	}

	public void setOrderSeqNum(int orderSeqNum) {
		this.orderSeqNum = orderSeqNum;
	}

	public int getKeycapNum() {
		return keycapNum;
	}

	public void setKeycapNum(int keycapNum) {
		this.keycapNum = keycapNum;
	}
	
	public String getKeycapName() {
		return keycapName;
	}

	public void setKeycapName(String keycapName) {
		this.keycapName = keycapName;
	}

	public int getOrderStock() {
		return orderStock;
	}

	public void setOrderStock(int orderStock) {
		this.orderStock = orderStock;
	}

	public int getOrderPrice() {
		return orderPrice;
	}

	public void setOrderPrice(int orderPrice) {
		this.orderPrice = orderPrice;
	}

	public String getOrderImg() {
		return orderImg;
	}

	public void setOrderImg(String orderImg) {
		this.orderImg = orderImg;
	}

	public String getOrderUserName() {
		return orderUserName;
	}

	public void setOrderUserName(String orderUserName) {
		this.orderUserName = orderUserName;
	}

	public String getOrderTel() {
		return orderTel;
	}

	public void setOrderTel(String orderTel) {
		this.orderTel = orderTel;
	}

	public String getOrderCall() {
		return orderCall;
	}

	public void setOrderCall(String orderCall) {
		this.orderCall = orderCall;
	}

	public String getOrderAddress() {
		return orderAddress;
	}

	public void setOrderAddress(String orderAddress) {
		this.orderAddress = orderAddress;
	}

	public String getOrderMsg() {
		return orderMsg;
	}

	public void setOrderMsg(String orderMsg) {
		this.orderMsg = orderMsg;
	}

	public String getOrderPay() {
		return orderPay;
	}

	public void setOrderPay(String orderPay) {
		this.orderPay = orderPay;
	}

	public String getOrderCard() {
		return orderCard;
	}

	public void setOrderCard(String orderCard) {
		this.orderCard = orderCard;
	}

	public int getOrderCardPlan() {
		return orderCardPlan;
	}

	public void setOrderCardPlan(int orderCardPlan) {
		this.orderCardPlan = orderCardPlan;
	}

	public String getOrderTelPlan() {
		return orderTelPlan;
	}

	public void setOrderTelPlan(String orderTelPlan) {
		this.orderTelPlan = orderTelPlan;
	}

	public String getOrderState() {
		return orderState;
	}

	public void setOrderState(String orderState) {
		this.orderState = orderState;
	}

	public Date getOrderPayDate() {
		return orderPayDate;
	}

	public void setOrderPayDate(Date orderPayDate) {
		this.orderPayDate = orderPayDate;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String getUserTel() {
		return userTel;
	}

	public void setUserTel(String userTel) {
		this.userTel = userTel;
	}

	public String getUserAddress() {
		return userAddress;
	}

	public void setUserAddress(String userAddress) {
		this.userAddress = userAddress;
	}

	public MultipartFile getUploadFile() {
		return uploadFile;
	}

	public void setUploadFile(MultipartFile uploadFile) {
		this.uploadFile = uploadFile;
	}

	public List<KeycapVo> getKeycap() {
		return keycap;
	}

	public void setKeycap(List<KeycapVo> keycap) {
		this.keycap = keycap;
	}
	
	
}
