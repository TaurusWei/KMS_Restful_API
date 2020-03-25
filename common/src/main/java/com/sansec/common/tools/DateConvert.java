package com.sansec.common.tools;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * 
 * @ClassName: DateConvert.java (日期转换类)
 * @author wangtao
 * @version V1.0
 * @Date 2015-7-21
 */
public class DateConvert {

	private DateConvert() {
		super();
		// 自动生成的构造函数存根
	}

	/**
	 * 
	 * (日期转字符串)
	 * 
	 * @author wangtao
	 * @version V1.0
	 * @Date 2015-7-21
	 */
	public static String dateToStr(Date date) {
		String str = null;
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(TimeZone.getDefault());
		str = sdf.format(date);
		return str;
	}

	/**
	 * 
	 * (字符转日期)
	 * 
	 * @author wangtao
	 * @version V1.0
	 * @Date 2015-7-21
	 */
	public static Date strToDate(String str) {
		Date date = null;

		try {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
			sdf.setTimeZone(TimeZone.getDefault());
			date = sdf.parse(str);
		} catch (ParseException e) {
			// Auto-generated catch block
			e.printStackTrace();
		}

		return date;
	}

	/**
	 * 
	 * (系统时间转字符串)
	 * 
	 * @author wangtao
	 * @version V1.0
	 * @Date 2015-7-21
	 */
	public static String sysTimeToStr() {
		String str = null;
		Date date = new Date();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		str = sdf.format(date);
		return str;
	}
	

    
  /**  
   * 计算两个日期之间相差的天数  
   * @param smdate 较小的时间 
   * @param bdate  较大的时间 
   * @return 相差天数 
   * @throws ParseException  
   */    
  public static int daysBetween(Date smdate,Date bdate) throws ParseException    
  {    
      SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd");  
      smdate=sdf.parse(sdf.format(smdate));  
      bdate=sdf.parse(sdf.format(bdate));  
      Calendar cal = Calendar.getInstance();    
      cal.setTime(smdate);    
      long time1 = cal.getTimeInMillis();                 
      cal.setTime(bdate);    
      long time2 = cal.getTimeInMillis();         
      long between_days=(time2-time1)/(1000*3600*24);  
          
     return Integer.parseInt(String.valueOf(between_days));           
  }    
    
/** 
*字符串的日期格式的计算 
*/  
  public static int daysBetween(String smdate,String bdate) throws ParseException{  
      SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd");  
      Calendar cal = Calendar.getInstance();    
      cal.setTime(sdf.parse(smdate));    
      long time1 = cal.getTimeInMillis();                 
      cal.setTime(sdf.parse(bdate));    
      long time2 = cal.getTimeInMillis();         
      long between_days=(time2-time1)/(1000*3600*24);  
          
     return Integer.parseInt(String.valueOf(between_days));     
  }  
	
	/**
	 * 
	 * (日期计算)
	 * 
	 * @author 
	 * @version 
	 * @throws ParseException 
	 * @Date 
	 */
	public static Date countDays(Date day,int days) throws ParseException {
		  SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd");  
	      day=sdf.parse(sdf.format(day));  
	      Calendar cal = Calendar.getInstance();    
	      cal.setTime(day);    
	      long time1 = cal.getTimeInMillis();
	      long time2=(long)1000*3600*24*days+time1;  
	      cal.setTimeInMillis(time2);
	      return cal.getTime();
	}
	
	public static void main(String[] args) throws Exception{
		
		SimpleDateFormat sdf=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");  
	        Date d1=sdf.parse("2012-10-15 10:10:10");  
	        Date d2=sdf.parse("2012-10-15 00:00:00");  
	        //System.out.println(daysBetween(d1,d2));  
	  
	        //System.out.println(daysBetween("2012-09-08 10:10:10","2012-09-15 00:00:00"));
	     
		SimpleDateFormat sdf1=new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");  
        Date d12=sdf1.parse("2017-09-08 10:10:10");  
        //System.out.println(sdf1.format(countDays(new Date(), 1000)));
        
       //System.out.println( DateConvert.dateToStr(DateConvert.countDays(DateConvert.strToDate("2012-09-08 10:10:10"),1000)));
        
        
	}

}
