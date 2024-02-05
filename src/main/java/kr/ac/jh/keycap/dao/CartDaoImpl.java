package kr.ac.jh.keycap.dao;

import java.util.List;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Repository;

import kr.ac.jh.keycap.model.CartVo;

@Repository
public class CartDaoImpl implements CartDao {
	
	@Autowired
	SqlSession sql;
	
	@Override
	public List<CartVo> list(String userId) {		
		return sql.selectList("cart.list",userId);
	}

	@Override
	public void add(CartVo item) throws DataAccessException {
		sql.insert("cart.add", item);
	}

	@Override
	public CartVo item(int cartNum) {
		return sql.selectOne("cart.item", cartNum);
	}

	@Override
	public void update(CartVo item) {
		sql.update("cart.update", item);
	}

	@Override
	public void delete(int cartNum) {
		sql.delete("cart.delete", cartNum);
	}

	@Override
	public boolean selectCountInCart(CartVo item) throws DataAccessException {
		String result = sql.selectOne("cart.selectCountInCart", item);
		return Boolean.parseBoolean(result);
	}

	@Override
	public CartVo item(CartVo cartNum) {
		return sql.selectOne("cart.item", cartNum);
	}
	
}
