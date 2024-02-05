package kr.ac.jh.keycap.service;

import java.util.List;

import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.util.Pager;

public interface HeartService {

	List<HeartVo> list(String userId, Pager pager);	
}
