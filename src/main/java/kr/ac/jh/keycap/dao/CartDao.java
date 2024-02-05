package kr.ac.jh.keycap.dao;

import java.util.List;

import kr.ac.jh.keycap.model.CartVo;
import kr.ac.jh.keycap.util.Pager;

public interface CartDao {
	
	List<CartVo> list(String userId);

	void add(CartVo item);

	CartVo item(int cartNum);

	void update(CartVo item);

	void delete(int cartNum);

	boolean selectCountInCart(CartVo item);

	CartVo item(CartVo cartNum);

}
