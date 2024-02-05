package kr.ac.jh.keycap.model;

import java.util.List;

public class HeartVo {
	int heartNum;
	int keycapNum;
	String userId;
	
	List<KeycapVo> keycap;
	
	public int getHeartNum() {
		return heartNum;
	}
	public void setHeartNum(int heartNum) {
		this.heartNum = heartNum;
	}
	public int getKeycapNum() {
		return keycapNum;
	}
	public void setKeycapNum(int keycapNum) {
		this.keycapNum = keycapNum;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public List<KeycapVo> getKeycap() {
		return keycap;
	}
	public void setKeycap(List<KeycapVo> keycap) {
		this.keycap = keycap;
	}
	
}
