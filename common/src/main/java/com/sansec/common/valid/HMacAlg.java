package com.sansec.common.valid;



import com.sansec.common.config.KeepAll;

import javax.validation.Constraint;
import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import javax.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;
import java.util.Arrays;

/**
 * Decription:hmac 数据校验
 * @author wangtao
 * create on 2018/1/8.
 */
@Constraint(validatedBy = HMacAlg.HMacAlgValidator.class)
@Target({java.lang.annotation.ElementType.METHOD,
		java.lang.annotation.ElementType.FIELD})
@Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@Documented
@KeepAll
public @interface HMacAlg {

	String message() default "{Support HmacSM3, HmacSHA1, HmacSHA256, HmacSHA384, HmacSHA512, HmacSHA224}";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};


	class HMacAlgValidator implements ConstraintValidator<HMacAlg, String> {

		private final String[] HMAC_ALG = {"HMACSM3", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512", "HMACSHA224"};

		@Override
		public void initialize(HMacAlg constraintAnnotation) {

		}


		@Override
		public boolean isValid(String value, ConstraintValidatorContext context) {
			value = value.replaceAll(" ", "");

			value = value.toUpperCase();

			return Arrays.asList(HMAC_ALG).contains(value);

		}

	}
}
