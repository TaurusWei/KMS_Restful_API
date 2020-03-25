package com.sansec.common.tools;

import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.SCPClient;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2019/6/4 23:29
 */
public class FileTools {
    private static final String DEFAULTPATH = "C:" + File.separator + "SANSECDB";
    public String test(String fileName) {
        String hostIp = null;
        String userName = null;
        String password = null;
        String directory = null;

        Connection conn = new Connection(hostIp);
        try {
            conn.connect();
            boolean isAuthenticated = conn.authenticateWithPassword(userName, password);
            if (!isAuthenticated) {
                return "Error！Please make sure the correctness of username and password.";
            }
            SCPClient client = new SCPClient(conn);
            client.put(fileName, directory); //本地文件scp到远程目录
            conn.close();
            return "success";
        } catch (IOException e) {
            e.printStackTrace();
            if (e.getMessage().contains("Error during SCP transfer.")) {
                return "Error！Please make sure the existence of the directory. Also,you should have the the permission to operator the folder.";
            } else {
                return "Error！Please make sure the correctness of the ip.";
            }

        }

    }
    /**
     * @Description: 使用默认目录 c:/SANSECDB
     * @param filePath
     * @param fname
     * @param msg
     *            void
     * @author wangtao
     * @date 2016年12月27日 上午11:00:43
     */
    public static void writeStringMsg(String filePath, String fname, String msg) {
        if ((filePath == null) || (filePath.equals(""))) {
            filePath = DEFAULTPATH;
        }
        File file = new File(filePath + File.separator + fname);
        if (file.exists()) {
            long size = file.length() / 1024 / 1024;
            if (size > 500) {
                file.delete();
            }
        }
        try {
            FileWriter write = new FileWriter(file, true);
            write.write(msg);
            write.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * @Description: 指定父目录
     * @param filePath
     * @param parent
     * @param fname
     * @param msg
     *            void
     * @author wangtao
     * @date 2016年12月27日 上午11:00:33
     */
    public static void writeStringMsg(String filePath, String parent, String fname, String msg) {
        if ((filePath == null) || (filePath.equals(""))) {
            filePath = DEFAULTPATH;
        }

        if (!parent.equals("")) {
            filePath += File.separator + parent + File.separator + fname;

        }
        File file = new File(filePath);
        if (file.exists()) {
            long size = file.length() / 1024 / 1024;
            if (size > 100) {
                file.delete();
            }
        } else {
            file.getParentFile().mkdirs();
            try {
                file.createNewFile();
            } catch (IOException e) {
                // TODO 自动生成的 catch 块
                e.printStackTrace();
            }

        }
        try {
            FileWriter write = new FileWriter(file, true);
            write.write(msg);
            write.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static String writeBakFile(String filePath, String bakmsg, boolean flag, String type) {

        String filename = UUID.randomUUID().toString().toLowerCase().replace("-", "");

        if ((filePath == null) || (filePath.equals(""))) {
            filePath = DEFAULTPATH;
        }
        File file = new File(filePath + File.separator + filename + "." + type);
        if (file.exists()) {
            long size = file.length() / 1024 / 1024;
            if (size > 200) {
                file.delete();
            }
        } else {
            try {
                file.createNewFile();
            } catch (IOException e) {

                e.printStackTrace();
            }
        }
        try {
            FileWriter write = new FileWriter(file, flag);
            write.write(bakmsg);
            write.close();
            // 清理之前数据备份文件

            File folder = new File(DEFAULTPATH);
            File[] files = folder.listFiles();
            for (File f : files) {
                if (f.getName().endsWith(".swd") && !f.getName().contains("c_platform")
                        && !f.getName().contains(filename)) {
                    f.delete();
                }

            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        return filename;
    }

    public static List<HashMap> readLastNLine(File file, long numRead) {
        List<HashMap> list= new ArrayList<HashMap>();
        String result = "";
        long count = 0;
        if (!file.exists() || file.isDirectory() || !file.canRead()) {
            return null;
        }
        RandomAccessFile fileRead = null;

        try {
            fileRead = new RandomAccessFile(file, "r");
            long length = fileRead.length();
            if (length == 0L) {
                return null;
            } else {
                long pos = length;
                while (pos > 0) {
                    pos--;
                    fileRead.seek(pos);
                    if (fileRead.readByte() == '\n'||pos==0) {
                        String line = fileRead.readLine();
                        //处理中文的乱码问题(原文件编码格式为utf-8)
                        if(line!=null&&line!="") {
                            line = new String(line.getBytes("8859_1"), "utf-8");
                            int wordCount = line.length();
                            int lineNum = wordCount/140+1;
                            if(line.length()>140) {
                                for(int i=1;i<lineNum;i++){
                                    line = FileTools.Stringinsert(line, "\n", 140*i);
                                }
                            }
                            HashMap<String,String> temp =new HashMap<String,String>();
                            temp.put("log", line);
                            list.add(temp);
                            count++;
                        }


                        if (count == numRead) {
                            break;
                        }
                    }

                }
//			Collections.reverse(list);
                if (pos == 0) {
                    fileRead.seek(0);
                }
                if (fileRead != null) {
                    fileRead.close();
                }
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return list;
    }

    public static List<HashMap> intervalReader(String filePath, int start, int finish) {
        List<HashMap> list = new ArrayList<>();

        if (start > finish) {
            System.out.println("Error start or finish!");
            return null;
        }
        InputStream inputStream = null;
        LineNumberReader reader = null;
        try {
            inputStream = new FileInputStream(new File(filePath));
            reader = new LineNumberReader(
                    new InputStreamReader(inputStream));
//             int lines = getTotalLines(new File(filePath));
            int lines = 0;
//             if (start < 0 || finish < 0 || finish > lines || start > lines) {
//                  System.out.println("Line not found!");
//                  return;
//             }

            String line = reader.readLine();
            lines = 0;
            while (line != null) {
                HashMap<String,String> temp =new HashMap<String,String>();
                lines++;
                if(lines >= start && lines <= finish){
                    if(line.length()>140) {
                        line = Stringinsert(line, "\n", 140);
                    }
                    temp.put("log", line);
                    list.add(temp);
                }
                line = reader.readLine();
                if(lines>finish) {
                    break;
                }
            }
            inputStream.close();
            reader.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
            System.err.println("IO Error");
            System.exit(0);
        }

        return list;

    }

    public static int getTotalLines(File file) throws IOException{
        FileReader in = new FileReader(file);
        LineNumberReader reader = new LineNumberReader(in);
        String line = reader.readLine();
        int lines = 0;
        while (line != null) {
            lines++;
            line = reader.readLine();
        }
        reader.close();
        in.close();
        return lines;
    }

    public static void MoveFolderAndFileWithSelf(String from, String to) throws Exception {
        try {
            File dir = new File(from);
            // 目标
            to +=  File.separator + dir.getName();
            File moveDir = new File(to);
            if(dir.isDirectory()){
                if (!moveDir.exists()) {
                    moveDir.mkdirs();
                }
            }else{
                File tofile = new File(to);
                dir.renameTo(tofile);
                return;
            }

            ////System.out.println("dir.isDirectory()"+dir.isDirectory());
            ////System.out.println("dir.isFile():"+dir.isFile());

            // 文件一览
            File[] files = dir.listFiles();
            if (files == null)
                return;

            // 文件移动
            for (int i = 0; i < files.length; i++) {
                //System.out.println("文件名："+files[i].getName());
                if (files[i].isDirectory()) {
                    MoveFolderAndFileWithSelf(files[i].getPath(), to);
                    // 成功，删除原文件
                    files[i].delete();
                }
                File moveFile = new File(moveDir.getPath() + File.separator + files[i].getName());
                // 目标文件夹下存在的话，删除
                if (moveFile.exists()) {
                    moveFile.delete();
                }
                files[i].renameTo(moveFile);
            }
            dir.delete();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }

    public static File[] listSortedFiles(File[] files) {

        FileWrapper [] fileWrappers = new FileWrapper[files.length];
        for (int i=0; i<files.length; i++) {
            fileWrappers[i] = new FileWrapper(files[i]);
        }

        Arrays.sort(fileWrappers);

        File []sortedFiles = new File[files.length];
        for (int i=0; i<files.length; i++) {
            sortedFiles[i] = fileWrappers[i].getFile();
        }

        return sortedFiles;
    }

    public static String Stringinsert(String a,String b,int t){
        return a.substring(0,t)+b+a.substring(t,a.length());
    }

    //返回MB
    public static int GetFileSize(File file){
        int size = -1;
        if(file.exists() && file.isFile()){
            long fileS = file.length();
            if (file.isFile()) {
                size = ((int) fileS / 1048576);
            }else if(file.exists() && file.isDirectory()){
                size = 0;
            }else{
                size = 0;
            }
        }
        return size;
    }


    public static String readFileByLine(String filePath,int lineNum) throws Exception {
        File file = new File(filePath);
        FileInputStream fis = new FileInputStream(file);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis));
        String str = null;
        int count=0;
        StringBuffer sb=new StringBuffer();
        while ((str = br.readLine()) != null) {
            count++;
            if(count>lineNum) {
                break;
            }
            if(count>lineNum-1){
                sb.append(str);
            }

        }
        br.close();
        fis.close();
        return sb.toString();
    }
    public static byte[] readFromFile(String fileName) throws IOException{
        byte[] data = null;
        File file = new File(fileName);
        data = new byte[new Long(file.length()).intValue()];
        FileInputStream in = new FileInputStream(file);

        in.read(data);

        in.close();

        return data;
    }
    public static void writeToFile(String fileName,byte[] data) throws IOException{
        FileOutputStream out = new FileOutputStream(fileName);
        out.write(data);
        out.close();
    }

    /**
     *
     * 获取目录下所有文件
     *
     * @param realpath
     * @param files
     * @return
     */
    public static List<File> getFiles(String realpath, List<File> files) {
        File realFile = new File(realpath);
        if (realFile.isDirectory()) {
            File[] subfiles = realFile.listFiles();
            for (File file : subfiles) {
                if (file.isDirectory()) {
                    getFiles(file.getAbsolutePath(), files);
                } else {
                    files.add(file);
                }
            }
        }
        return files;
    }

    /**
     * 获取文件的修改时间
     * @param fullFileName
     */
    public static String getModifiedTime(String fullFileName){
        File file = new File(fullFileName);
        if (!file.exists()){
            return "";
        }
        BasicFileAttributes bAttributes = null;
        try {
            bAttributes = Files.readAttributes(file.toPath(),BasicFileAttributes.class);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 修改时间
        FileTime fileTime = bAttributes.lastModifiedTime();

        ZonedDateTime ztime1=ZonedDateTime.ofInstant(fileTime.toInstant(), ZoneId.systemDefault());
        String time1 = ztime1.toLocalDateTime().toString().replace("T"," ");
//        System.out.println(time1);

        return time1.split("\\.")[0];
    }

}


