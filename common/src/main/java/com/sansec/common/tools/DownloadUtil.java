package com.sansec.common.tools;

import com.sansec.common.exception.GlobalException;
import com.sansec.common.result.CodeMsg;
import com.sansec.common.result.Result;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.URLEncoder;

public class DownloadUtil {

	private static final Logger logger = LoggerFactory.getLogger(DownloadUtil.class);

	public static Result downloadSuccess(HttpServletRequest request, HttpServletResponse response, String sName,
										 byte[] value) {
		try {
			String filename = URLEncoder.encode(sName, "UTF-8").replaceAll("\\+", "%20");
			ServletOutputStream out = response.getOutputStream();
			response.setCharacterEncoding("utf-8");
			response.setContentType("application/x-download");
			response.setHeader("Content-Disposition", "attachment;fileName=" + filename);
			out.write(value);
			out.flush();
			out.close();
			return Result.success("");
		} catch (IOException e) {
			//todo
			e.printStackTrace();
			throw new GlobalException(CodeMsg.DOWNLOAD_CERT_ERROR.fillArgs(e.getMessage()));
//			String sMsg = "downloadSuccess error";
//			logger.error(sMsg, e);
//			response.reset();
//			downloadError(request, response, "下载失败:" + e.getMessage());
		}

	}

	public static void downloadError(HttpServletRequest request, HttpServletResponse response, String sErrMsg) {
		try {

			String retUrl = request.getHeader("referer");

			response.setContentType("text/html;charset=utf-8");
			PrintWriter writer = response.getWriter();
			writer.println("<script>");
			writer.println("alert('" + sErrMsg + "');");
			if (StringUtils.isEmpty(retUrl)) {
				writer.println("window.location.href='" + retUrl + "'");
			}
			writer.println("</script>");
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
			String sMsg = "downloadError error";
			logger.error(sMsg, e);
		}
	}
	public static void download(HttpServletRequest request, HttpServletResponse response, String packageWithSign) throws IOException {
//		System.out.println("文件路径是："+packageWithSign);
		try {
			File file = new File(packageWithSign);
			if (file.exists()) {
				String filename = file.getName();
				InputStream fis = new BufferedInputStream(new FileInputStream( file));   //用BufferedInputStream读取文件
				response.reset();
				response.setContentType("application/x-download");
				response.addHeader("Content-Disposition","attachment;filename="+ new String(filename.getBytes(),"iso-8859-1"));
				response.addHeader("Content-Length", "" + file.length());
				OutputStream toClient = new BufferedOutputStream(response.getOutputStream());
				response.setContentType("application/octet-stream");
				byte[] buffer = new byte[1024];
				int i = -1;
				while ((i = fis.read(buffer)) != -1) {   //不能一次性读完，大文件会内存溢出（不能直接fis.read(buffer);）
					toClient.write(buffer, 0, i);
				}
				fis.close();
				toClient.flush();
				toClient.close();
			} else {
				PrintWriter out = response.getWriter();
				out.print("<script>");
				out.print("alert(\"not find the file\")");
				out.print("</script>");
			}
		} catch (IOException ex) {
			ex.printStackTrace();
			PrintWriter out = response.getWriter();
			out.print("<script>");
			out.print("alert(\"not find the file\")");
			out.print("</script>");
		}
	}
}
