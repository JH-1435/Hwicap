package kr.ac.jh.keycap.controller;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;

import kr.ac.jh.keycap.model.HeartVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.service.HeartService;
import kr.ac.jh.keycap.service.KeycapService;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/heart")
public class HeartController {
	final String path = "heart/";
	
	@Autowired
	HeartService service;
	
	@Autowired
	KeycapService serviceKeycap;
	
	//Date 형식을 스프링에게 어떤값으로 변환될지 알려줌
	@InitBinder
	private void dataBinder(WebDataBinder binder) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
					
		CustomDateEditor editor = new CustomDateEditor(dateFormat, true);
					
		binder.registerCustomEditor(Date.class, editor);
	}
					
	//Model에 list를 담아두면 jsp페이지에 전달할 수 있다.
	@GetMapping("/{userId}/list")
	String list(@PathVariable("userId") String userId, Model model, Pager pager) {
		pager.setPerPage(20); // 한페이지 당 20개 보여줌
		List<HeartVo> list = service.list(userId, pager);
		
		model.addAttribute("list", list);
		
		return path + "list";
	}
}
