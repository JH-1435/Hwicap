package kr.ac.jh.keycap.model;

import java.util.Date;
import java.util.List;

public class CartVo {
	
	int cartNum;
	String userId;
	int keycapNum;
	int cartCount;
	Date cartDate;
	
	String userName;
	
	List<KeycapVo> keycap;
	List<UserVo> user;
	
	public int getCartNum() {
		return cartNum;
	}

	public void setCartNum(int cartNum) {
		this.cartNum = cartNum;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public int getKeycapNum() {
		return keycapNum;
	}

	public void setKeycapNum(int keycapNum) {
		this.keycapNum = keycapNum;
	}

	public int getCartCount() {
		return cartCount;
	}

	public void setCartCount(int cartCount) {
		this.cartCount = cartCount;
	}

	public Date getCartDate() {
		return cartDate;
	}

	public void setCartDate(Date cartDate) {
		this.cartDate = cartDate;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}
	
	public List<KeycapVo> getKeycap() {
		return keycap;
	}

	public void setKeycap(List<KeycapVo> keycap) {
		this.keycap = keycap;
	}

	public List<UserVo> getUser() {
		return user;
	}

	public void setUser(List<UserVo> user) {
		this.user = user;
	}
	
}
