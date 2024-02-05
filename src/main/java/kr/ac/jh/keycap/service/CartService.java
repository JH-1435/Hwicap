package kr.ac.jh.keycap.service;

import java.util.List;

import java.util.Map;

import kr.ac.jh.keycap.model.CartVo;
import kr.ac.jh.keycap.model.KeycapVo;

public interface CartService {

	List<CartVo> list(String userId);

	void add(CartVo item) throws Exception;

	CartVo item(int cartNum);

	void update(CartVo item);

	void delete(int cartNum);
	
	void orders(String userId, int cartCount, Map<Integer, KeycapVo> content);

	boolean findCartKeycapNum(CartVo item) throws Exception;

	CartVo item(CartVo cartNum);
}
