package demo.merchant;


import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

/**
 * @Description 密码学
 * @ClassName Cryptology
 * @Author xiexw
 */
public class Cryptology {

    public static void main(String[] args) throws Exception {

//        String str ="汉字";
//        byte[] bytes = str.getBytes();
//        for (byte b : bytes) {
//            System.out.println(b);
//            System.out.println(Integer.toBinaryString(b));
//        }
//        String input = "汉字123";
//        byte[] key = Base64.getDecoder().decode("J77YMVNob6EZ3Y8BNFEn6w==");
//        String transformation = "AES/ECB/PKCS5Padding";
//        String algorithm = "AES";
//        System.out.println("原文：" + input);
//        String output = desEncrypt(input, key, transformation, algorithm);
//        System.out.println("密文：" + output);
//        System.out.println("解密后：" + desDecrypt(output,key,transformation, algorithm));


//        String input = "123";
//        String algorithm = "MD5";
//        System.out.println(digest(input,algorithm));
//        String algorithm2 = "SHA-1";
//        System.out.println(digest(input,algorithm2));
//        String algorithm3 = "SHA-256";
//        System.out.println(digest(input,algorithm3));
//
        String algorithm = "MD5withRSA";
//        generateKeyPair(algorithm);

        //创建密钥生成器对象
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //生成私钥
        PrivateKey privateKey = keyPair.getPrivate();
        //生成公钥
        PublicKey publicKey = keyPair.getPublic();
        String input = "汉字12";
        getSignature(input,algorithm,publicKey,privateKey);
    }

    /**
     * 对称加密
     * @param input 原文
     * @param key 加密密钥
     * @param transformation 算法
     * @param algorithm 加密类型
     * @return
     */
    private static String desEncrypt(String input,byte[] key,String transformation,String algorithm) throws Exception {
        //创建jdk自带加解密类
        Cipher cipher = Cipher.getInstance(transformation);
        //创建加密规则类
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,algorithm);
        //加密初始化
        cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);
        //加密
        byte[] bytes = cipher.doFinal(input.getBytes());
        //Base64编码
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 对称解密
     * @param output 密文
     * @param key 加密密钥
     * @param transformation 算法
     * @param algorithm 加密类型
     * @return
     */
    private static String desDecrypt(String output, byte[] key, String transformation, String algorithm) throws Exception{
        //base64解码
        byte[] decode = Base64.getDecoder().decode(output);
        //创建jdk自带加解密类
        Cipher cipher = Cipher.getInstance(transformation);
        //创建加密规则类
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,algorithm);
        //加密初始化
        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec);
        //解密
        return new String(cipher.doFinal(decode));
    }


    /**摘要加密
     * @param input 原文
     * @param algorithm 摘要算法  例如MD5
     * @return 密文
     * @throws Exception
     */
    private static String digest(String input, String algorithm) throws Exception{
        //创建消息摘要对象
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        //执行消息摘要算法
        byte[] bytes = digest.digest(input.getBytes());
        //base64编码
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 生成密钥对 并加密、解密
     * @param algorithm 加密方式
     */
    private static void generateKeyPair(String algorithm) throws Exception{
        //创建密钥生成器对象
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //生成私钥
        PrivateKey privateKey = keyPair.getPrivate();
        //生成公钥
        PublicKey publicKey = keyPair.getPublic();
        //打印公私钥
        System.out.println("privateKey: " +Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("publicKey: " +Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        //加密
        Cipher cipher = Cipher.getInstance(algorithm);
        //加密初始化
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        //加密
        String input = "汉字";
        byte[] bytes = cipher.doFinal(input.getBytes());
        System.out.println("加密后密文："+ Base64.getEncoder().encodeToString(bytes));

        //解密初始化
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        //解密
        byte[] bytes1 = cipher.doFinal(bytes);
        System.out.println("解密后："+new String(bytes1));
    }

    /**
     * 数字签名及验签
     * @param input 原文
     * @param algorithm 签名模式
     * @param privateKey 签名私钥
     * @param publicKey 签名公钥
     */
    private static void getSignature(String input,String algorithm,PublicKey publicKey,PrivateKey privateKey) throws Exception{
        //获取签名对象
        Signature signature = Signature.getInstance(algorithm);
        //初始化签名
        signature.initSign(privateKey);
        //传入原文
        signature.update(input.getBytes());
        //签名
        byte[] bytes = signature.sign();
        System.out.println("签名后："+Base64.getEncoder().encodeToString(bytes));

        //验签
        //初始化密钥
        signature.initVerify(publicKey);
        //传入原文
        signature.update(input.getBytes());
        //验签
        boolean verify = signature.verify(bytes);
        System.out.println("验签结果："+verify);
    }
}
