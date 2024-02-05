package kr.ac.jh.keycap.service;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.util.Pager;

public interface KeycapService {
	List<KeycapVo> list(Pager pager);

	void add(KeycapVo item);

	KeycapVo item(int keycapNum);

	void update(KeycapVo item);

	void delete(int keycapNum);

	void init();

	void dummy();
	
	void keycapReadCount(int keycapNum);

	boolean findHeartKeycapNum(HeartVo item) throws Exception;
	
	void keycapLike(HeartVo item) throws Exception;

	void keycapLikeMa(HeartVo item) throws Exception;

	void updateKeycapStock(KeycapVo keycap);

	void updateKeycapOrder(KeycapVo keycap);

	List<KeycapVo> listBest(Pager pager);

	List<KeycapVo> listPriceDesc(Pager pager);

	List<KeycapVo> listPriceAsc(Pager pager);

	List<KeycapVo> listReviewDesc(Pager pager);
	
}
