package kr.ac.jh.keycap.service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.dao.HeartDao;
import kr.ac.jh.keycap.dao.KeycapDao;
import kr.ac.jh.keycap.util.Pager;

@Service
public class KeycapServiceImpl implements KeycapService {

	@Autowired
	KeycapDao dao;
	
	@Autowired
	HeartDao hDao;	
	
	@Override
	public List<KeycapVo> list(Pager pager) {
		int total = dao.total(pager);
		
		pager.setTotal(total);
		
		return dao.list(pager);
	}
	
	@Override
	public void add(KeycapVo item) {
		dao.add(item);
	}

	@Override
	public KeycapVo item(int keycapNum) {
		return dao.item(keycapNum);
	}

	@Override
	public void update(KeycapVo item) {
		dao.update(item);
	}

	@Override
	public void delete(int keycapNum) {
		dao.delete(keycapNum);
	}

	@Override
	public void init() {
		Pager pager = new Pager();
		pager.setPage(1);
		
		while(dao.total(pager) > 0) {
			List<KeycapVo> list = dao.list(pager);
			
			for(KeycapVo item : list)
				dao.delete(item.getKeycapNum());
		}

	}

	@Override
	public void dummy() {
		KeycapVo item = new KeycapVo();
		for(int index=1; index < 100; index++) {
			
			item.setKeycapId("Hwicap" + index);
			item.setKeycapName("상품명" + index);
			item.setKeycapStock(index);
			item.setKeycapPrice(1000 + index);
			item.setKeycapImg("더미 텍스트");
			item.setKeycapCategory("키캡");
			dao.add(item);
		}
	}
	
	@Override
	public void keycapReadCount(int keycapNum) {
		dao.keycapReadCount(keycapNum);

	}
	
	@Override
	public boolean findHeartKeycapNum(HeartVo item) throws Exception {
		return hDao.selectCountInHeart(item);
	}
	
	@Override
	public void keycapLike(HeartVo item) throws Exception {
		hDao.add(item);
		dao.keycapLike(item);
	}
	
	@Override
	public void keycapLikeMa(HeartVo item) throws Exception {
		hDao.delete(item);
		dao.keycapLikeMa(item);
	}
	
	@Override
	public void updateKeycapStock(KeycapVo keycap) {
		dao.updateKeycapStock(keycap);
	}

	@Override
	public void updateKeycapOrder(KeycapVo keycap) {
		dao.updateKeycapOrder(keycap);
	}

	@Override
	public List<KeycapVo> listBest(Pager pager) {
		int total = dao.total(pager);
		pager.setTotal(total);
		return dao.listBest(pager);
	}

	@Override
	public List<KeycapVo> listPriceDesc(Pager pager) {
		int total = dao.total(pager);
		pager.setTotal(total);
		return dao.listPriceDesc(pager);
	}

	@Override
	public List<KeycapVo> listPriceAsc(Pager pager) {
		int total = dao.total(pager);
		pager.setTotal(total);
		return dao.listPriceAsc(pager);
	}

	@Override
	public List<KeycapVo> listReviewDesc(Pager pager) {
		int total = dao.total(pager);
		pager.setTotal(total);
		return dao.listReviewDesc(pager);
	}
}
