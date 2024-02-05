package kr.ac.jh.keycap.dao;

import java.util.List;
import java.util.Map;

import kr.ac.jh.keycap.model.HeartVo;

public interface HeartDao {

	boolean selectCountInHeart(HeartVo item);
	
	void add(HeartVo item);

	void delete(HeartVo item);
	
	int total(Map<String, Object> list);

	List<HeartVo> list(Map<String, Object> list);
}
