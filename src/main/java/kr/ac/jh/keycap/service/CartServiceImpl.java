package kr.ac.jh.keycap.service;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import kr.ac.jh.keycap.dao.CartDao;
import kr.ac.jh.keycap.dao.OrdersDao;
import kr.ac.jh.keycap.model.CartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.OrdersVo;

@Service
@Transactional(propagation = Propagation.REQUIRED)
public class CartServiceImpl implements CartService {
	@Autowired
	CartDao dao;
	
	@Autowired
	OrdersDao daoOrders;
	
	@Override
	public List<CartVo> list(String userId) {			
		return dao.list(userId);
	}

	@Override
	public void add(CartVo item) throws Exception {
		dao.add(item);
	}

	@Override
	public CartVo item(int cartNum) {
		return dao.item(cartNum);
	}

	@Override
	public void update(CartVo item) {
		dao.update(item);
	}

	@Override
	public void delete(int cartNum) {
		dao.delete(cartNum);
	}
	
	@Override
	@Transactional
	public void orders(String userId, int cartCount, Map<Integer, KeycapVo> content) {
			CartVo item = new CartVo();
			
			item.setUserId(userId);

			item.setCartCount(cartCount);
			
			dao.add(item);
			
			
			//keySet()은 Map이 담겨있는 cotent의 key값만 사용
			for(int keycapNum : content.keySet()) {			
				OrdersVo orders = new OrdersVo();
				
				orders.setKeycapNum(keycapNum);
				
				daoOrders.add(orders);
			} 
	}

	@Override
	public boolean findCartKeycapNum(CartVo item) throws Exception {
		
		return dao.selectCountInCart(item);
	}

	@Override
	public CartVo item(CartVo cartNum) {
		return dao.item(cartNum);
	}

	
}
