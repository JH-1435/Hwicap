package kr.ac.jh.keycap.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import kr.ac.jh.keycap.dao.KeycapDao;
import kr.ac.jh.keycap.dao.OrdersDao;
import kr.ac.jh.keycap.model.CartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.util.Pager;

@Service
public class OrdersServiceImpl implements OrdersService {

	@Autowired
	OrdersDao dao;
	
	@Autowired
	KeycapDao keycapDao;
	
	//관리자가 모든 유저 구매내역 보기
	@Override
	public List<OrdersVo> list(Pager pager) {
		int total = dao.total(pager);
		
		pager.setTotal(total);
		
		return dao.list(pager) ;
	}
	
	//유저 구매내역보기 - dao에서 selectList는 하나의 Object parameter를 쓸수 있으므로 map에 담아 한꺼번에 보낸다.
	@Override
	public List<OrdersVo> listUser(String userId, Pager pager) {
		Map<String, Object> list = new HashMap<String, Object>();
		list.put("userId", userId);
		list.put("pager",  pager);

		int total = dao.totalUser(list);
		pager.setTotal(total);
		
		return dao.listUser(list);
	}
	
	@Override
	public OrdersVo item(int orderSeqNum) {
		return dao.item(orderSeqNum);
	}

	@Override
	public void update(OrdersVo item) {
		dao.update(item);
	}

	@Override
	public void delete(int orderSeqNum) {
		dao.delete(orderSeqNum);
	}

	@Override
	@Transactional
	public void order(String userId, String userName, String userTel, String userAddress, int cartCount, int total,
			String orderImg, String orderUserName, String orderTel, String orderCall, String orderAddress_final,
			String orderMsg, String orderPay, String orderCard, int orderCardPlan, String orderTelPlan,
			Map<Integer, KeycapVo> content) {
		//주문자 정보 설정
		OrdersVo item = new OrdersVo();	
		item.setUserId(userId);
		item.setUserName(userName);
		item.setUserTel(userTel);
		item.setUserAddress(userAddress);
		
		item.setOrderUserName(orderUserName);
		item.setOrderTel(orderTel);
		item.setOrderCall(orderCall);
		item.setOrderAddress(orderAddress_final);
		item.setOrderMsg(orderMsg);
		item.setOrderPay(orderPay);
		item.setOrderCard(orderCard);
		item.setOrderCardPlan(orderCardPlan);
		item.setOrderTelPlan(orderTelPlan);
		item.setOrderState("결제완료");
		
		for(int keycapNum : content.keySet()) {
			KeycapVo keycap = content.get(keycapNum);
			
			item.setOrderImg(orderImg);
			item.setKeycapNum(keycapNum);
			item.setKeycapName(keycap.getKeycapName());
			item.setOrderStock(cartCount);
			item.setOrderPrice(total);
			
			dao.add(item);
			
			//결제 완료 시 해당 상품 수량 수정
			keycap.setKeycapStock(keycap.getKeycapStock() - cartCount);
			keycapDao.updateKeycapStock(keycap); 
		}
	}

	@Override
	public void orderCart(String userId, String userName, String userTel, String userAddress, String orderUserName,
			String orderTel, String orderCall, String orderAddress_final, String orderMsg, String orderPay,
			String orderCard, int orderCardPlan, String orderTelPlan, Map<Integer, CartVo> list) {
		//주문자 정보 설정
		OrdersVo item = new OrdersVo();	

			item.setUserId(userId);
			item.setUserName(userName);
			item.setUserTel(userTel);
			item.setUserAddress(userAddress);
					
			item.setOrderUserName(orderUserName);
			item.setOrderTel(orderTel);
			item.setOrderCall(orderCall);
			item.setOrderAddress(orderAddress_final);
			item.setOrderMsg(orderMsg);
			item.setOrderPay(orderPay);
			item.setOrderCard(orderCard);
			item.setOrderCardPlan(orderCardPlan);
			item.setOrderTelPlan(orderTelPlan);
			item.setOrderState("결제완료");
			
			for(int cartNum : list.keySet()) {	
			CartVo cart = list.get(cartNum);
			KeycapVo keycap = keycapDao.item(cart.getKeycapNum());
			
			item.setOrderImg(keycap.getKeycapImg());
			item.setKeycapNum(cart.getKeycapNum());
			item.setKeycapName(keycap.getKeycapName());
			item.setOrderStock(cart.getCartCount());
			item.setOrderPrice(cart.getCartCount() * keycap.getKeycapPrice());
			
			dao.add(item);
			
			//결제 완료 시 해당 상품 수량 수정
			keycap.setKeycapStock(keycap.getKeycapStock() - cart.getCartCount());
			keycapDao.updateKeycapStock(keycap);
		}
	}

	@Override
	public void updateMsg(OrdersVo item) {
		dao.updateMsg(item);
	}
	
}
