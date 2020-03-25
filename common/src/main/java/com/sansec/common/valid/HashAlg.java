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
 * Decription:摘要算法
 * @author wangtao
 * create on 2018/1/8.
 */
@Constraint(validatedBy = HashAlg.DigestAlgValidator.class)
@Target({java.lang.annotation.ElementType.METHOD,
		java.lang.annotation.ElementType.FIELD})
@Retention(java.lang.annotation.RetentionPolicy.RUNTIME)
@Documented
@KeepAll
public @interface HashAlg {

	String message() default "{Support SHA1、SHA224、SHA256、SHA384、SHA512、SM3}";

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};


	class DigestAlgValidator implements ConstraintValidator<HashAlg, String> {
		private final String[] HASH_ALG = {"SHA1", "SHA224","SHA256", "SHA384", "SHA512", "SM3"};


		@Override
		public void initialize(HashAlg constraintAnnotation) {

		}


		@Override
		public boolean isValid(String value, ConstraintValidatorContext context) {
			value = value.replaceAll(" ", "");
			value = value.toUpperCase();

			return Arrays.asList(HASH_ALG).contains(value);
		}
	}
}
