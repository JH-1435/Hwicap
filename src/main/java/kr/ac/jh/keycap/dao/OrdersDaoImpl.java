package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.util.Pager;

@Repository
public class OrdersDaoImpl implements OrdersDao {
	
	@Autowired
	SqlSession sql;
	
	//관리자가 모든 유저 구매내역 보기
	@Override
	public List<OrdersVo> list(Pager pager) {
		return sql.selectList("orders.list", pager);
	}
	
	//유저 구매내역보기 - serviceImpl에서 전달한 map을 그대로 받아 적용한다.
	@Override
	public List<OrdersVo> listUser(Map<String, Object> list) {
		return sql.selectList("orders.listUser", list);
	}
	
	@Override
	public void add(OrdersVo orders) {
		sql.insert("orders.add", orders);
	}
	
	@Override
	public void update(OrdersVo item) {
		sql.update("orders.update", item);
	}
	
	@Override
	public void delete(int orderSeqNum) {
		sql.delete("orders.delete", orderSeqNum);
	}
	
	@Override
	public OrdersVo item(int orderSeqNum) {
		return sql.selectOne("orders.item", orderSeqNum);
	}

	@Override
	public int total(Pager pager) {	
		return sql.selectOne("orders.total", pager);
	}

	@Override
	public int totalUser(Map<String, Object> list) {
		return sql.selectOne("orders.totalUser", list);
	}

	@Override
	public void updateMsg(OrdersVo item) {
		sql.update("orders.updateMsg", item);
	}
}
