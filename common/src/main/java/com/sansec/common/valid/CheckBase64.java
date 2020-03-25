package com.sansec.common.valid;

import com.sansec.common.config.KeepAll;
import org.apache.commons.codec.binary.Base64;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Decription:hmac 数据校验
 * @author wangtao
 * create on 2018/1/8.
 */
@Constraint(validatedBy = CheckBase64.PaddingValidator.class)
@Target({java.lang.annotation.ElementType.METHOD,
		java.lang.annotation.ElementType.FIELD})
@Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@Documented
@KeepAll
public @interface CheckBase64 {

	String message() default "{Characters need to be encoded in Base64}";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};


	class PaddingValidator implements ConstraintValidator<CheckBase64, String> {


		@Override
		public void initialize(CheckBase64 constraintAnnotation) {

		}


		@Override
		public boolean isValid(String value, ConstraintValidatorContext context) {
			if (null != value) {


				return (value.length() > 0 && Base64.isBase64(value) && value.length() % 4 == 0);
			} else {
				return true;
			}


		}

	}
}
