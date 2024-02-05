package kr.ac.jh.keycap.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.service.AdminService;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/admin")
public class AdminController {
	final String path = "admin/";
	
	@Autowired
	AdminService service;
		
	//Model에 list를 담아두면 jsp페이지에 전달할 수 있다.
	@GetMapping("/list")
	String list(Pager pager, Model model) {
		List<AdminVo> list = service.list(pager);
		
		model.addAttribute("list", list);
		
		return path + "list";
		
	}
	
	// @ResponseBody를 하면 뷰리졸버가 jsp를 찾지않고, 후처리를 하지않고 그대로 클라이언트에게 보내주는 지시를 함
	@ResponseBody
	// id가 null 이면 OK, 아니면 FAIL => 중복검사를 했을때 아이디가 없으면 OK, 있으면 FAIL
	@GetMapping("/confirmId")
	String confirmId(String adminId) {
		if (service.item(adminId) == null) {
			return "OK";
		}

		return "FAIL";
	}
		
	@GetMapping("/add")
	String add() {
		return path + "add";
	}
	
	@PostMapping("/add")
	String add(AdminVo item) {
		service.add(item);
		
		return "redirect:list";
	}
	
	@GetMapping("/{adminId}/update")
	String update(@PathVariable String adminId, Model model) {
		AdminVo item = service.item(adminId);
		
		model.addAttribute("item", item);
		
		return path + "update";
	}
	
	@PostMapping("/{adminId}/update")
	String update(@PathVariable String adminId, AdminVo item) {
		item.setAdminId(adminId);
		
		service.update(item);
		
		return "redirect:../list";
	}
	
	@GetMapping("/{adminId}/delete")
	String delete(@PathVariable String adminId) {
		service.delete(adminId);
		
		return "redirect:../list";
	}
}

