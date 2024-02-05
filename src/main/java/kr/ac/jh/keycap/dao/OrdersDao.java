package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.util.Pager;

public interface OrdersDao {
	
	void add(OrdersVo orders);

	int total(Pager pager);

	List<OrdersVo> list(Pager pager);

	OrdersVo item(int orderSeqNum);

	void delete(int orderSeqNum);

	void update(OrdersVo item);
	
	List<OrdersVo> listUser(Map<String, Object> list);

	int totalUser(Map<String, Object> list);

	void updateMsg(OrdersVo item);	
}
