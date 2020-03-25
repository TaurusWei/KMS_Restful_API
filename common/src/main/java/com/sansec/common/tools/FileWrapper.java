package com.sansec.common.tools;

import java.io.File;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2019/6/8 12:47
 */
public class FileWrapper {
    /** File */
    private File file;

    public FileWrapper(File file) {
        this.file = file;
    }

    public int compareTo(Object obj) {
        assert obj instanceof FileWrapper;

        FileWrapper castObj = (FileWrapper)obj;

        if (this.file.getName().compareTo(castObj.getFile().getName()) > 0) {
            return 1;
        } else if (this.file.getName().compareTo(castObj.getFile().getName()) < 0) {
            return -1;
        } else {
            return 0;
        }
    }

    public File getFile() {
        return this.file;
    }
}
