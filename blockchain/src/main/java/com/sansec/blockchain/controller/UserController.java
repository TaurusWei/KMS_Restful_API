package com.sansec.blockchain.controller;

import com.sansec.blockchain.service.UserService;
import com.sansec.common.result.Result;
import com.sansec.model.UserModel;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/2/27 0027 15:40
 */
@Api(tags = "1、用户模块", description = "用户模块 Rest API")
@RequestMapping(value = "/user")
@RestController
public class UserController {
    @Autowired
    UserService userService;

    @ApiOperation("用户登录")
    @PostMapping(value = "/login",consumes="application/json",produces = "application/json")
    @ResponseBody
    public Result createNew(@RequestBody @Validated UserModel userModel) {

        return userService.login(userModel);
    }
}
