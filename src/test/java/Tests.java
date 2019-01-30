/**    Created by IntelliJ IDEA.
    Author: Yinyx
    Date: 2019/1/30
    */
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import utils.CertUtils;
import utils.KeyUtils;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.KeyPair;
import java.util.Date;

public class Tests {
    @Test
    public void test() throws Exception{
        //生成密钥对
        KeyPair eccrootcakey = KeyUtils.generateKeyPair("ecc");
        KeyPair sm2rootcakey  = KeyUtils.generateKeyPair("sm2");
        KeyPair rsarootcakey  = KeyUtils.generateKeyPair("rsa");
        KeyPair ecckey = KeyUtils.generateKeyPair("ecc");
        KeyPair sm2key  = KeyUtils.generateKeyPair("sm2");
        KeyPair rsakey  = KeyUtils.generateKeyPair("rsa");
        //生成证书请求
        PKCS10CertificationRequest eccCsr = CertUtils.generateCSR(new X500Name("C=CN,CN=ECCEntityCert"),ecckey.getPublic(),ecckey.getPrivate());
        PKCS10CertificationRequest sm2Csr = CertUtils.generateCSR(new X500Name("C=CN,CN=SM2EntityCert"),sm2key.getPublic(),sm2key.getPrivate());
        PKCS10CertificationRequest rsaCsr = CertUtils.generateCSR(new X500Name("C=CN,CN=RSAEntityCert"),rsakey.getPublic(),rsakey.getPrivate());
        //验证证书请求
        assert CertUtils.verifyCSR(sm2Csr);
        assert CertUtils.verifyCSR(eccCsr);
        assert CertUtils.verifyCSR(rsaCsr);
        System.out.println(getPemStr(eccCsr));
        System.out.println(getPemStr(sm2Csr));
        System.out.println(getPemStr(rsaCsr));
        //自签发根证书
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + 1000L*60L*60L*24L*365L);   //365天
        Certificate eccCaCert = CertUtils.selfSignedCertGen(new X500Name("C=CN,CN=ECCRootCa"),eccrootcakey,notBefore,notAfter);
        Certificate sm2CaCert = CertUtils.selfSignedCertGen(new X500Name("C=CN,CN=SM2RootCa"),sm2rootcakey,notBefore,notAfter);
        Certificate rsaCaCert = CertUtils.selfSignedCertGen(new X500Name("C=CN,CN=RSARootCa"),rsarootcakey,notBefore,notAfter);
        //根证书签发生成实体证书
        Certificate eccEntityCert = CertUtils.certGen(eccCsr,eccrootcakey.getPrivate(),eccCaCert.getEncoded(),notBefore,notAfter);
        Certificate sm2EntityCert = CertUtils.certGen(sm2Csr,sm2rootcakey.getPrivate(),sm2CaCert.getEncoded(),notBefore,notAfter);
        Certificate rsaEntityCert = CertUtils.certGen(rsaCsr,rsarootcakey.getPrivate(),rsaCaCert.getEncoded(),notBefore,notAfter);
        //写入证书DER到文件
        writeFile(eccCaCert.getEncoded(),"eccRootCert.cer");
        writeFile(sm2CaCert.getEncoded(),"sm2RootCert.cer");
        writeFile(rsaCaCert.getEncoded(),"rsaRootCert.cer");
        writeFile(eccEntityCert.getEncoded(),"eccEntityCert.cer");
        writeFile(sm2EntityCert.getEncoded(),"sm2EntityCert.cer");
        writeFile(rsaEntityCert.getEncoded(),"rsaEntityCert.cer");
    }

    public String getPemStr(Object obj) throws Exception{
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(bos));
        pemWriter.writeObject(obj);
        pemWriter.flush();
        pemWriter.close();
        return bos.toString();
    }

    public void writeFile(byte[] data, String path) throws Exception{
        File f = new File(path);
        if(!f.exists()) {
            f.createNewFile();
        }
        FileOutputStream out = new FileOutputStream(f);
        out.write(data);
        out.close();
    }
}
