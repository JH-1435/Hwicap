package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.util.Pager;

public interface KeycapDao {
	
	List<KeycapVo> list(Pager pager);

	void add(KeycapVo item);

	KeycapVo item(int keycapNum);

	void update(KeycapVo item);

	void delete(int keycapNum);

	int total(Pager pager);
	
	void keycapReadCount(int keycapNum);

	void keycapLike(HeartVo item);

	void keycapLikeMa(HeartVo item);
	
	void updateKeycapStock(KeycapVo keycap);

	void updateKeycapOrder(KeycapVo keycap);

	List<KeycapVo> listBest(Pager pager);

	List<KeycapVo> listPriceDesc(Pager pager);

	List<KeycapVo> listPriceAsc(Pager pager);

	List<KeycapVo> listReviewDesc(Pager pager);
}
