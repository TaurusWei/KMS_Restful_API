package com.sansec.fabricsdk;

import lombok.Data;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.protos.common.Common.*;

import java.io.Serializable;
import java.security.Security;
import java.util.Set;

/**
 * @Author: WeiBingtao/13156050650@163.com
 * @Version: 1.0
 * @Description:
 * @Date: 2020/3/14 0014 17:54
 */
@Data
public class UserContext implements User , Serializable {

    private String name;
    private Set<String> roles;
    private String account;
    private String affiliation;
    private Enrollment enrollment;
    private String mspId;
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
