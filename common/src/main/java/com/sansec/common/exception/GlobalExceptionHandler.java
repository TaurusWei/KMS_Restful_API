package com.sansec.common.exception;

import com.sansec.common.result.CodeMsg;
import com.sansec.common.result.Result;
import com.sansec.common.tools.LogTool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description: 异常处理器
 * @Date: 2019/1/27 19:46
 */

@ControllerAdvice   //该注解一般只有处理异常有用
@ResponseBody
public class GlobalExceptionHandler {
    Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    //声明处理的异常类
    @ExceptionHandler(value = Exception.class)
    public Result<String> exceptionHandler(HttpServletRequest request, Exception e) {

        e.printStackTrace();
        if (e instanceof GlobalException) {
            GlobalException globalException = (GlobalException) e;
            logger.error(LogTool.failLog(globalException.getCodeMsg()));
            return Result.error(globalException.getCodeMsg());
        } else if (e instanceof BindException) {
            //    绑定失败，如表单对象参数违反约束
            BindException bindException = (BindException) e;
            logger.error(LogTool.failLog(CodeMsg.PARAMETER_VALID_ERROR.fillArgs(buildMessages(bindException.getBindingResult()))));
            return Result.error(CodeMsg.PARAMETER_VALID_ERROR.fillArgs(buildMessages(bindException.getBindingResult())));
        } else if(e instanceof MethodArgumentNotValidException){
            //    参数无效，如JSON请求参数违反约束
            MethodArgumentNotValidException methodArgumentNotValidException= (MethodArgumentNotValidException) e;
            logger.error(CodeMsg.PARAMETER_VALID_ERROR.fillArgs(buildMessages(methodArgumentNotValidException.getBindingResult())).getMsg());
            return Result.error(CodeMsg.PARAMETER_VALID_ERROR.fillArgs(buildMessages(methodArgumentNotValidException.getBindingResult())));
        }else {
            logger.error(CodeMsg.SERVER_ERROR.getMsg());
            return Result.error(CodeMsg.SERVER_ERROR);
        }
    }
    private String buildMessages(BindingResult result) {
        StringBuilder resultBuilder = new StringBuilder();

        List<ObjectError> errors = result.getAllErrors();
        if (errors != null && errors.size() > 0) {
            for (ObjectError error : errors) {
                if (error instanceof FieldError) {
                    FieldError fieldError = (FieldError) error;
//                    String fieldName = fieldError.getField();
                    String fieldErrMsg = fieldError.getDefaultMessage();
                    resultBuilder.append(fieldErrMsg).append(";");
                }
            }
        }
        return resultBuilder.toString();
    }
}
