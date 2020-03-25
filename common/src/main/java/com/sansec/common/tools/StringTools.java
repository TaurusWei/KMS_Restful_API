package com.sansec.common.tools;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

public class StringTools {

	public static boolean isEmpty(String s) {
		if (s == null || s.trim().length() == 0) {
			return true;
		}
		return false;
	}

	public static String toDateString(Date date) {
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		return format.format(date);
	}

	public static String toDateStringMonth(Date date) {
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM");
		return format.format(date);
	}

	public static String toDateStringDay(Date date) {
		SimpleDateFormat format = new SimpleDateFormat("-yyyy-MM-dd");
		return format.format(date);
	}

	public static Date toDate(String date) throws ParseException {
		SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		return format.parse(date);
	}
}
