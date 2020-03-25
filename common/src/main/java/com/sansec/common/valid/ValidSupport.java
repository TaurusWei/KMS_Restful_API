package com.sansec.common.valid;


import com.alibaba.fastjson.JSON;
import com.sansec.common.config.KeepAll;
import org.apache.commons.lang3.StringUtils;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.Arrays;

/**
 * Decription:摘要算法
 * @author wangtao
 * create on 2018/1/8.
 */
@Constraint(validatedBy = ValidSupport.DigestAlgValidator.class)
@Target({java.lang.annotation.ElementType.METHOD,
		java.lang.annotation.ElementType.FIELD})
@Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@Documented
@KeepAll
public @interface ValidSupport {

	/**
	 * 这三个方法是必须要有的
	 */
	String message() default "";
	Class<?>[] groups() default {};
	Class<? extends Payload>[] payload() default {};

	/**
	 * 自己定义方法
	 */
	String[] supportAlg() default "";

	class DigestAlgValidator implements ConstraintValidator<ValidSupport, String> {

		private String[] algArray;

		@Override
		public void initialize(ValidSupport constraintAnnotation) {
			algArray = constraintAnnotation.supportAlg();
			for (int i = 0; i < algArray.length; i++) {
				algArray[i] = algArray[i].toUpperCase();
			}

		}


		@Override
		public boolean isValid(String value, ConstraintValidatorContext context) {
			if(StringUtils.isNotBlank(value)){

				value = value.replaceAll(" ", "");
				value = value.toUpperCase();

				System.out.println(value);
				System.out.println(algArray);

				System.out.println(JSON.toJSONString(Arrays.asList(algArray)));

				return Arrays.asList(algArray).contains(value);
			}else{
				return false;
			}
		}
	}
}
