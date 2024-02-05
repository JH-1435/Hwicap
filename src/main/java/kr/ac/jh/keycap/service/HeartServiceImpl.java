package kr.ac.jh.keycap.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import kr.ac.jh.keycap.dao.HeartDao;
import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.util.Pager;

@Service
public class HeartServiceImpl implements HeartService {
	
	@Autowired
	HeartDao dao;
	
	@Override
	public List<HeartVo> list(String userId, Pager pager) {
		Map<String, Object> list = new HashMap<String, Object>();
		list.put("userId", userId);
		list.put("pager",  pager);
		
		int total = dao.total(list);
		pager.setTotal(total);
		
		return dao.list(list);
	}
}
