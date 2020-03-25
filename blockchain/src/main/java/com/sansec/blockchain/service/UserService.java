package com.sansec.blockchain.service;

import com.sansec.common.result.CodeMsg;
import com.sansec.common.result.Result;
import com.sansec.common.token.TokenManager;

import com.sansec.model.UserModel;
import com.sansec.persistence.mapper.UserMapper;
import com.sansec.persistence.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import tk.mybatis.mapper.entity.Example;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/2/27 0027 15:40
 */
@Service
public class UserService {
    @Value("${tokenTimeOut}")
    String tokenTimeOut;

    @Autowired
    UserMapper userMapper;

    public Result login(UserModel userModel) {
        //可以在token中存放用户自定义的键值对
        Map<String,Object> map = new HashMap<>();
        Example example = new Example(User.class);
        Example.Criteria criteria = example.createCriteria();
        criteria.andEqualTo("username", userModel.getUserName());
        criteria.andEqualTo("password", userModel.getPasswd());
        List userList = userMapper.selectByExample(example);
        if (userList.size()==1){
            String jwt = TokenManager.createJWT(userModel.getUserName(), Integer.parseInt(tokenTimeOut), "",map);
            return Result.success(jwt);
        }
        return Result.error(CodeMsg.LOGIN_ERROR);
    }
}
