package com.sansec.model;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/2/27 0027 17:08
 */
@Data
@ApiModel("UserModel（用户实体）")
public class UserModel {
    @ApiModelProperty(value = "用户名",name = "userName",example = "sansec")
    @NotBlank(message="User name can not be null")
    String userName;
    @ApiModelProperty(value = "密码",name = "passwd",example = "Sansec1234.")
//    @NotBlank(message="Password can not be null")
//    @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[$@$!%*#?&])[A-Za-z\\d$@$!%*#?&]{8,}$",message = "Password consists of at least 8 characters, at least 1 letter, 1 number, and 1 special character.")
    String passwd;
}
