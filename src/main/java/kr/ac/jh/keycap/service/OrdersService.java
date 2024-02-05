package kr.ac.jh.keycap.service;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.CartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.util.Pager;

public interface OrdersService {

	OrdersVo item(int orderSeqNum);

	List<OrdersVo> list(Pager pager);
	
	void update(OrdersVo item);

	void delete(int orderSeqNum);
	
	void order(String userId, String userName, String userTel, String userAddress, int cartCount, int total,
			String orderImg, String orderUserName, String orderTel, String orderCall, String orderAddress_final,
			String orderMsg, String orderPay, String orderCard, int orderCardPlan, String orderTelPlan,
			Map<Integer, KeycapVo> content);

	void orderCart(String userId, String userName, String userTel, String userAddress, String orderUserName,
			String orderTel, String orderCall, String orderAddress_final, String orderMsg, String orderPay,
			String orderCard, int orderCardPlan, String orderTelPlan, Map<Integer, CartVo> list);

	List<OrdersVo> listUser(String userId, Pager pager);

	void updateMsg(OrdersVo item);
}
