package kr.ac.jh.keycap.controller;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import kr.ac.jh.keycap.model.AdminVo;
import kr.ac.jh.keycap.model.KeycapVo;
import kr.ac.jh.keycap.model.OrdersVo;
import kr.ac.jh.keycap.model.UserVo;
import kr.ac.jh.keycap.service.KeycapService;
import kr.ac.jh.keycap.service.OrdersService;
import kr.ac.jh.keycap.util.Pager;

@Controller
@RequestMapping("/orders")
public class OrdersController {
	final String path = "orders/";
	
	@Autowired
	OrdersService service;
	
	@Autowired
	KeycapService serviceKeycap;
	
	//Date 형식을 스프링에게 어떤값으로 변환될지 알려줌
	@InitBinder
	private void dataBinder(WebDataBinder binder) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
				
		CustomDateEditor editor = new CustomDateEditor(dateFormat, true);
				
		binder.registerCustomEditor(Date.class, editor);
	}
			
	//주문내역 -> 주문한 상품 상세정보 보기
	@GetMapping("/{orderSeqNum}/view")
	String view(@PathVariable int orderSeqNum, Model model) {
		OrdersVo item = service.item(orderSeqNum);
		
		model.addAttribute("item", item);
		
		return path + "view";
	}
	
	// 관리자가 주문내역 보기
	@GetMapping("/listAdmin")
	String list(Model model, Pager pager) {
		List<OrdersVo> list = service.list(pager);
		
		model.addAttribute("list", list);
		
		return path + "listAdmin";
	}
	
	
	//회원 각각의 주문내역 보기
	@GetMapping("/{userId}/list")
	String list(@PathVariable("userId") String userId,
			Model model,  Pager pager) {
		
		List<OrdersVo> list = service.listUser(userId, pager);
				
		model.addAttribute("list", list);
		
		return path + "list";
	}
			
	//주문정보 변경
	@GetMapping("/{orderSeqNum}/update")
	String update(@PathVariable int orderSeqNum, Model model) {
		OrdersVo item = service.item(orderSeqNum);
		
		model.addAttribute("item", item);
		
		return path + "update";
	}
	
	@PostMapping("/{orderSeqNum}/update")
	String update(@PathVariable int orderSeqNum, OrdersVo item) {
		service.update(item);
		
		return "redirect:../list";
	}
	
	//배송상태 변경
	@GetMapping("/{orderSeqNum}/updateMsg")
	String updateMsg(@PathVariable int orderSeqNum, Model model) {
		OrdersVo item = service.item(orderSeqNum);
			
		model.addAttribute("item", item);
			
		return path + "updateMsg";
	}
	//배송상태 변경	
	@PostMapping("/{orderSeqNum}/updateMsg")
	String updateMsg(@PathVariable int orderSeqNum, OrdersVo item, HttpSession session) {
		UserVo user = (UserVo) session.getAttribute("user");
		// keycapNum에 해당하는 KeycapVo 객체를 데이터베이스에서 가져옴
		KeycapVo keycap = serviceKeycap.item(item.getKeycapNum());
		
		AdminVo admin = (AdminVo) session.getAttribute("admin");
		
		if(item.getOrderState().equals("001") && admin != null)
		{
			item.setUserId(item.getUserId());
			String state = "배송중";
			item.setOrderState(state);
		}
		else if(item.getOrderState().equals("002") && user != null)
		{
			item.setUserId(user.getUserId());
			String state = "구매확정";
			item.setOrderState(state);
						
			if (keycap != null) {
			    keycap.setKeycapOrder(item.getOrderStock());
			    serviceKeycap.updateKeycapOrder(keycap);
	        }
			
		}
		else if(item.getOrderState().equals("003") && user != null)
		{									
			item.setUserId(user.getUserId());
			String state = "결제취소";
			item.setOrderState(state);
			
			if (keycap != null) {
			    keycap.setKeycapStock(keycap.getKeycapStock() + item.getOrderStock());
			    serviceKeycap.updateKeycapStock(keycap);
	        }
		}
		
		service.updateMsg(item);
		
		if(admin != null)
		{
			return "redirect:../" + "listAdmin";
		}
		else
		{
			return "redirect:../" + user.getUserId() + "/list";
		}
	}
		
	//주문취소
	@GetMapping("/{orderSeqNum}/delete")
	String delete(@PathVariable int orderSeqNum) {
		service.delete(orderSeqNum);
		
		return "redirect:../list";
	}
	
}
