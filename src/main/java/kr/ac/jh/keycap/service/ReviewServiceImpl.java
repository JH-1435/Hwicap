package kr.ac.jh.keycap.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import kr.ac.jh.keycap.dao.ReviewDao;
import kr.ac.jh.keycap.model.ReviewVo;
import kr.ac.jh.keycap.util.Pager;

@Service
public class ReviewServiceImpl implements ReviewService {
	@Autowired
	ReviewDao dao;
	
	@Override
	public List<ReviewVo> list(int keycapNum, Pager pager) {
		Map<String, Object> list = new HashMap<String, Object>();
		list.put("keycapNum", keycapNum);
		list.put("pager",  pager);
		
		int total = dao.total(list);
		pager.setTotal(total);
		
		return dao.list(list);
	}

	@Override
	public List<ReviewVo> listUser(String userId, Pager pager) {
		Map<String, Object> list = new HashMap<String, Object>();
		list.put("userId", userId);
		list.put("pager",  pager);
		
		int total = dao.totalUser(list);
		pager.setTotal(total);
		
		return dao.listUser(list);
	}

	@Override
	public ReviewVo item(int reviewNum) {
		return dao.item(reviewNum);
	}

	@Override
	public void update(ReviewVo item) {
		dao.update(item);
	}

	@Override
	public void delete(int reviewNum) {
		dao.delete(reviewNum);
	}

	@Override
	public void add(ReviewVo item) {
		dao.add(item);
	}

	@Override
	public int totalReview(int keycapNum) {
		return dao.totalReview(keycapNum);
	}
	
}
