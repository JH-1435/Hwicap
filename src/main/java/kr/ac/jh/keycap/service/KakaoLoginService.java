package kr.ac.jh.keycap.service;

import java.util.HashMap;

public interface KakaoLoginService {
	
	//받아온 카카오 code 담음
	String getAccessToken(String authorize_code);

	public HashMap<String, Object> getUserInfo(String access_Token);
}
