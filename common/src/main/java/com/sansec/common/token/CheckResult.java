package com.sansec.common.token;


import io.jsonwebtoken.Claims;

/**
 * Decription:
 * @author wangtao
 * create on 2017/12/28.
 */
public class CheckResult {
	private int errCode;

	private boolean success;

	private Claims claims;

	public CheckResult() {
	}

	public int getErrCode() {
		return errCode;
	}

	public void setErrCode(int errCode) {
		this.errCode = errCode;
	}

	public boolean isSuccess() {
		return success;
	}

	public void setSuccess(boolean success) {
		this.success = success;
	}

	public Claims getClaims() {
		return claims;
	}

	public void setClaims(Claims claims) {
		this.claims = claims;
	}
}
