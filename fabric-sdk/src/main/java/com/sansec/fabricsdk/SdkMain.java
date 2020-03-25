package com.sansec.fabricsdk;

import org.hyperledger.fabric.protos.common.Ledger;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.*;
import org.hyperledger.fabric_ca.sdk.HFCAClient;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SdkMain {

    private static final Logger log = LoggerFactory.getLogger(SdkMain.class);

//    用户密钥目录
    private static final String keyFolderPath = "E:\\Work\\worklist\\KMS_Restful_API\\fabric-sdk\\src\\main\\resources\\crypto-config\\peerOrganizations\\org1.example.com\\users\\Admin@org1.example.com\\msp\\keystore";
//    密钥名称
    private static final String keyFileName="7a131739c86e3306e38f2b4fdf8bae88e85a22f272641cfa037e430736a44f6b_sk";
//    身份证书目录
    private static final String certFoldePath="E:\\Work\\worklist\\KMS_Restful_API\\fabric-sdk\\src\\main\\resources\\crypto-config\\peerOrganizations\\org1.example.com\\users\\Admin@org1.example.com\\msp\\admincerts";
//    身份证书名字
    private static final String certFileName="Admin@org1.example.com-cert.pem";
//    order节点的tls证书
    private static  final String tlsOrderFilePath = "E:\\Work\\worklist\\KMS_Restful_API\\fabric-sdk\\src\\main\\resources\\crypto-config\\ordererOrganizations\\example.com\\tlsca\\tlsca.example.com-cert.pem";
//    通道配置文件
    private static final String txfilePath = "E:\\Work\\worklist\\KMS_Restful_API\\fabric-sdk\\src\\main\\resources\\test.tx";
    private static  final String tlsPeerFilePath = "E:\\fabric\\src\\main\\resources\\crypto-config\\peerOrganizations\\org1.example.com\\peers\\peer0.org1.example.com\\msp\\tlscacerts\\tlsca.org1.example.com-cert.pem";
    private static  final String tlsPeerFilePathAddtion = "E:\\fabric\\src\\main\\resources\\crypto-config\\peerOrganizations\\org2.example.com\\tlsca\\tlsca.org2.example.com-cert.pem";
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, TransactionException, ProposalException, org.bouncycastle.crypto.CryptoException {

        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org1");
        userContext.setMspId("Org1MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment =  UserUtils.getEnrollment(keyFolderPath,keyFileName,certFoldePath,certFileName);
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        //Channel channel = fabricClient.getChannel("test");
        //channel.addOrderer(fabricClient.getOrderer("orderer.example.com","grpcs://orderer.example.com:7050",tlsOrderFilePath));
       Channel channel =  fabricClient.createChannel("test",fabricClient.getOrderer("orderer.example.com","grpcs://orderer.example.com:7050",tlsOrderFilePath),txfilePath);
        channel.joinPeer(fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath));
        channel.initialize();
    }

    //安装合约
    /*public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, TransactionException, ProposalException {

        List list = new ArrayList();
        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org2");
        userContext.setMspId("Org2MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment =  UserUtils.getEnrollment(keyFolderPath,keyFileName,certFoldePath,certFileName);
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        Peer peer0 = fabricClient.getPeer("peer0.org2.example.com","grpcs://peer0.org2.example.com:9051",tlsPeerFilePathAddtion);
        Peer peer1 = fabricClient.getPeer("peer1.org2.example.com","grpcs://peer1.org2.example.com:10051",tlsPeerFilePathAddtion);
        List<Peer> peers = new ArrayList<Peer>();
        peers.add(peer0);
        peers.add(peer1);
        fabricClient.installChaincode(TransactionRequest.Type.GO_LANG,"basicinfo","2.0","E:\\chaincode","basicinfo",peers);
    }*/

   //合约实例化
   /* public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, ProposalException, TransactionException {
        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org1");
        userContext.setMspId("Org1MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment =  UserUtils.getEnrollment(keyFolderPath,keyFileName,certFoldePath,certFileName);
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        Peer peer = fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath);
        Orderer order = fabricClient.getOrderer("orderer.example.com","grpcs://orderer.example.com:7050",tlsOrderFilePath);
        String initArgs[] = {""};
        fabricClient.initChaincode("mychannel", TransactionRequest.Type.GO_LANG,"basicinfo","1.0",order,peer,"init",initArgs);
    }*/

   //合约升级
    /*public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, ProposalException, TransactionException, ChaincodeEndorsementPolicyParseException {
        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org1");
        userContext.setMspId("Org1MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment =  UserUtils.getEnrollment(keyFolderPath,keyFileName,certFoldePath,certFileName);
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        Peer peer = fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath);
        Orderer order = fabricClient.getOrderer("orderer.example.com","grpcs://orderer.example.com:7050",tlsOrderFilePath);
        String initArgs[] = {""};
        fabricClient.upgradeChaincode("mychannel", TransactionRequest.Type.GO_LANG,"basicinfo","2.0",order,peer,"init",initArgs);
    }*/

    //invoke 合约
    /* public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, ProposalException, TransactionException, ChaincodeEndorsementPolicyParseException {
        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org2");
        userContext.setMspId("Org2MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment =  UserUtils.getEnrollment(keyFolderPath,keyFileName,certFoldePath,certFileName);
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        Peer peer0 = fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath);
        Peer peer1 = fabricClient.getPeer("peer0.org2.example.com","grpcs://peer0.org2.example.com:9051",tlsPeerFilePathAddtion);
        List<Peer> peers = new ArrayList<>();
        peers.add(peer0);
        peers.add(peer1);
        Orderer order = fabricClient.getOrderer("orderer.example.com","grpcs://orderer.example.com:7050",tlsOrderFilePath);
        String initArgs[] = {"110114","{\"name\":\"zhangsan\",\"identity\":\"110114\",\"mobile\":\"18910012222\"}"};
        fabricClient.invoke("mychannel", TransactionRequest.Type.GO_LANG,"basicinfo",order,peers,"save",initArgs);
    }*/

    //查询合约
   /*public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, ProposalException, TransactionException, org.bouncycastle.crypto.CryptoException {
        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org2");
        userContext.setMspId("Org2MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment =  UserUtils.getEnrollment(keyFolderPath,keyFileName,certFoldePath,certFileName);
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        Peer peer0 = fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath);
        Peer peer1 = fabricClient.getPeer("peer0.org2.example.com","grpcs://peer0.org2.example.com:9051",tlsPeerFilePathAddtion);
        List<Peer> peers = new ArrayList<>();
        peers.add(peer0);
        peers.add(peer1);
        String initArgs[] = {"110114"};
        Map map =  fabricClient.queryChaincode(peers,"mychannel", TransactionRequest.Type.GO_LANG,"basicinfo","query",initArgs);
        System.out.println(map);
    }*/

   //注册用户 hqCZUStrRTAR
   /*public static void main(String[] args) throws Exception {
        FabricCAClient caClient = new FabricCAClient("http://192.168.70.43",null);
        UserContext register = new UserContext();
        register.setName("lihua");
        register.setAffiliation("org2");
        Enrollment enrollment = caClient.enroll("admin","adminpw");
        UserContext registar = new UserContext();
        registar.setName("admin");
        registar.setAffiliation("org2");
        registar.setEnrollment(enrollment);
       String secret =  caClient.register(registar,register);
       System.out.println(secret);
    }*/

   //注册用户查询合约
//    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, CryptoException, ProposalException, TransactionException, org.bouncycastle.crypto.CryptoException, EnrollmentException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException {
//        FabricCAClient caClient = new FabricCAClient("http://192.168.70.43",null);
//        UserContext userContext = new UserContext();
//        userContext.setAffiliation("Org2");
//        userContext.setMspId("Org2MSP");
//        userContext.setAccount("李伟");
//        userContext.setName("admin");
//        Enrollment enrollment = caClient.enroll("lihua","hqCZUStrRTAR");
//        userContext.setEnrollment(enrollment);
//        FabricClient fabricClient = new FabricClient(userContext);
//        Peer peer0 = fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath);
//        Peer peer1 = fabricClient.getPeer("peer0.org2.example.com","grpcs://peer0.org2.example.com:9051",tlsPeerFilePathAddtion);
//        List<Peer> peers = new ArrayList<>();
//        peers.add(peer0);
//        peers.add(peer1);
//        String initArgs[] = {"110120"};
//        Map map =  fabricClient.queryChaincode(peers,"mychannel", TransactionRequest.Type.GO_LANG,"basicinfo","query",initArgs);
//        System.out.println(map);
//    }



    //注册用户invoke合约
    /*public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, CryptoException, IOException, IllegalAccessException, InvalidArgumentException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, org.hyperledger.fabric.sdk.exception.CryptoException, ProposalException, TransactionException, ChaincodeEndorsementPolicyParseException, EnrollmentException, org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException {
        FabricCAClient caClient = new FabricCAClient("http://192.168.70.43",null);
        UserContext userContext = new UserContext();
        userContext.setAffiliation("Org2");
        userContext.setMspId("Org2MSP");
        userContext.setAccount("李伟");
        userContext.setName("admin");
        Enrollment enrollment = caClient.enroll("lihua","hqCZUStrRTAR");
        userContext.setEnrollment(enrollment);
        FabricClient fabricClient = new FabricClient(userContext);
        Peer peer0 = fabricClient.getPeer("peer0.org1.example.com","grpcs://peer0.org1.example.com:7051",tlsPeerFilePath);
        Peer peer1 = fabricClient.getPeer("peer0.org2.example.com","grpcs://peer0.org2.example.com:9051",tlsPeerFilePathAddtion);
        List<Peer> peers = new ArrayList<>();
        peers.add(peer0);
        peers.add(peer1);
        Orderer order = fabricClient.getOrderer("orderer.example.com","grpcs://orderer.example.com:7050",tlsOrderFilePath);
        String initArgs[] = {"110120","{\"name\":\"zhangsan\",\"identity\":\"110120\",\"mobile\":\"18910012222\"}"};
        fabricClient.invoke("mychannel", TransactionRequest.Type.GO_LANG,"basicinfo",order,peers,"save",initArgs);
    }*/
}
