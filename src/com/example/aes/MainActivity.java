package com.example.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.os.Bundle;
import android.app.Activity;
import android.util.Log;
import android.view.Menu;
import android.widget.Toast;

public class MainActivity extends Activity {

	private static final String mode = "AES/ECB/PKCS5Padding";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
        	//String aa=cryptogram.encrypt("pws", "hello");
        	/*byte[] aa = aes("hello111","pws");
			Log.d("11111111",aa+"");
			Log.d("111111112", aesToByte(aa, "pws"));*/
        	
//        	String en = aesEncrypt("hello", "1234561234561234561234561234586546556465416546545");
//        	String dn = aesDecrypt(en, "1234561234561234561234561234586546556465416546545");
        	String en = aesEncrypt("hello", "123456");
        	String dn = aesDecrypt(en, "123456");
        	Toast.makeText(MainActivity.this, dn, 1).show();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    /**
     * AESº”√‹
     * @param content
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] aesEncrypt(byte[] content , String key){
    	/*KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "Crypto");
		sr.setSeed(key.getBytes());
    	keyGenerator.init(128,sr);
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.ENCRYPT_MODE, 
    			new SecretKeySpec(keyGenerator.generateKey().getEncoded(), "AES"));
    	return cipher.doFinal(content.getBytes("UTF-8"));*/
    	
    	
    	/*KeyGenerator kgen = KeyGenerator.getInstance("AES");
    	kgen.init(128, new SecureRandom(key.getBytes()));
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kgen.generateKey().getEncoded(), "AES"));
    	return cipher.doFinal(content.getBytes("UTF-8"));*/
    	try{
	    	SecretKeySpec secretKeySpec = createKey(key);
	    	Cipher cipher = Cipher.getInstance(mode);
	    	cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);
	    	byte[] result = cipher.doFinal(content);
	    	return result;
    	}catch(Exception e){
    		e.printStackTrace();
    	}
    	return null;
    }
    
    public static String aesEncrypt(String content, String pwd) {
    	byte[] data =null;
    	try {
			data = content.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	data = aesEncrypt(data,pwd);
    	String result = byte2hex(data);
    	return result;
		
	}
    
    private static String byte2hex(byte[] b) {
		StringBuffer sb = new StringBuffer(b.length * 2); 
		String tmp;
		for(int i=0;i<b.length;i++){
			tmp = Integer.toHexString(b[i]&0xFF);
			if(tmp.length() == 0){
				sb.append("0");
			}
			sb.append(tmp);
		}
		return sb.toString().toUpperCase();
	}
    /**
     * AESΩ‚√‹
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] aesDecrypt(byte[] data , String key){
    	/*KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
    	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "Crypto");
		sr.setSeed(key.getBytes());
    	keyGenerator.init(128,sr);
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.DECRYPT_MODE, 
    			new SecretKeySpec(keyGenerator.generateKey() .getEncoded(), "AES"));
    	byte[] decryptBytes =cipher.doFinal(data);
    	return new String(decryptBytes,"UTF-8");*/
    	
    	/*KeyGenerator kgen = KeyGenerator.getInstance("AES");
    	kgen.init(128, new SecureRandom(key.getBytes()));
    	Cipher cipher = Cipher.getInstance("AES");
    	cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kgen.generateKey() .getEncoded(), "AES"));
    	byte[] decryptBytes = cipher.doFinal(data);
    	return new String(decryptBytes,"UTF-8");*/
    	try{
	    	SecretKeySpec secretKeySpec = createKey(key);
	    	Cipher cipher =Cipher.getInstance(mode);
	    	cipher.init(Cipher.DECRYPT_MODE,secretKeySpec);
	    	byte[] result = cipher.doFinal(data);
	    	return result;
    	}catch(Exception e){
    		e.printStackTrace();
    	}
    	return null;
    }
    
    private static String aesDecrypt(String content, String pwd) {
    	byte[] data = null;
    	
    	data = hex2byte(content);
    	
    	data = aesDecrypt(data, pwd);
    	if(data == null){
    		return null;
    	}
    	String result = null;
    	
    	try {
			result = new String(data,"UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	return result;	
	}
    
    private static byte[] hex2byte(String hex) {
    	if(hex == null || hex.length()<2){
    		return new byte[0];
    	}
    	hex = hex.toLowerCase();
    	int len = hex.length() / 2;
    	byte[] result = new byte[len];
    	for(int i = 0 ;i<len;i++){
    		String tmp = hex.substring(i*2,i*2+2);
    		result[i] = (byte) (Integer.parseInt(tmp,16)&0XFF);
    	}
		return result;
	}
    
    private static SecretKeySpec createKey(String pwd) {
		byte [] data = null;
		if(pwd == null){
			pwd = "";
		}
		StringBuffer sb = new StringBuffer();
		sb.append(pwd);
		while(sb.length()<32){
			sb.append("0");
		}
		if(sb.length()>32){
			sb.setLength(32);
		}
		try {
			data = sb.toString().getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new SecretKeySpec(data, "AES");
	}
}
