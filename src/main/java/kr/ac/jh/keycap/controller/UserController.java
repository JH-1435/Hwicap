package kr.ac.jh.keycap.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.service.UserService;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/user")
public class UserController {
	final String path = "user/";
	
	@Autowired
	UserService service;
	
	//Model에 list를 담아두면 jsp페이지에 전달할 수 있다.
	@GetMapping("/list")
	String list(Pager pager, Model model) {
		List<UserVo> list = service.list(pager);
		
		model.addAttribute("list", list);
		
		return path + "list";
		
	}
	
	// @ResponseBody를 하면 뷰리졸버가 jsp를 찾지않고, 후처리를 하지않고 그대로 클라이언트에게 보내주는 지시를 함
	@ResponseBody
	// id가 null 이면 OK, 아니면 FAIL => 중복검사를 했을때 아이디가 없으면 OK, 있으면 FAIL
	@GetMapping("/confirmId")
	String confirmId(String userId) {
		if (service.item(userId) == null) {
			return "OK";
		}

		return "FAIL";
	}
	
	@GetMapping("/add")
	String add() {
		return path + "add";
	}
		
	@PostMapping("/add")
	String add(UserVo item, 
			@RequestParam String userAddress1, @RequestParam String userAddress2,
			@RequestParam String userTel1, @RequestParam String userTel2, @RequestParam String userTel3) {
		
		item.setUserAddress(userAddress1 + "@" + userAddress2);
		item.setUserTel(userTel1 + userTel2 + userTel3);
		service.add(item);

		return "redirect:" + "list";
	}
	
	@GetMapping("/{userId}/update")
	String update(@PathVariable String userId, Model model) {
		UserVo item = service.item(userId);
		
		model.addAttribute("item", item);
		
		return path + "update";
	}
	
	@PostMapping("/{userId}/update")
	String update(UserVo item, @PathVariable String userId,
			@RequestParam String userAddress1, @RequestParam String userAddress2,
			@RequestParam String userTel1, @RequestParam String userTel2, @RequestParam String userTel3) {
		item.setUserId(userId);
		item.setUserAddress(userAddress1 + "@" + userAddress2);
		item.setUserTel(userTel1 + userTel2 + userTel3);
		
		service.update(item);
		
		return "redirect:../list";
	}
	
	@GetMapping("/{userId}/delete")
	String delete(@PathVariable String userId) {
		service.delete(userId);
		
		return "redirect:../list";
	}
}

