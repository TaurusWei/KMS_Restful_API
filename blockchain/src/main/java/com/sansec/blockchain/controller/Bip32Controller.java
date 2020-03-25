package com.sansec.blockchain.controller;

import com.alibaba.fastjson.JSON;
import com.sansec.blockchain.service.Bip32Service;
import com.sansec.common.result.Result;
import com.sansec.persistence.mapper.UserMapper;
import com.sansec.persistence.model.User;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import tk.mybatis.mapper.entity.Example;

import java.util.List;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/2/26 0026 16:32
 */
@Api(tags = "2、密钥模块", description = "密钥模块 Rest API")
@RestController
@RequestMapping(value = "/key")
public class Bip32Controller {
    @Autowired
    Bip32Service bip32Service;
    @Autowired
    private UserMapper userMapper;

    @ApiOperation("创建密钥")
    @PostMapping(value = "/createNewKey",produces = "application/json")
    @ResponseBody
    public Result createNew(String seed) {
        Result result =new Result();
        if (StringUtils.isNotBlank(seed)){
            Example example = new Example(User.class);
            Example.Criteria criteria = example.createCriteria();
            criteria.andEqualTo("username", "admin");
            List backupSettingList = userMapper.selectByExample(example);
            System.out.println(JSON.toJSONString(backupSettingList));
        }else{
            result  = bip32Service.createNew();
        }
        return result;
    }
}
