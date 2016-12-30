package th.go.rd.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.KeyGenerator;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.JavaUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Encrypter {

	private static final Logger log = LoggerFactory.getLogger(Encrypter.class);

    private String certificateFile;
	private String inputFile;
	private String outputFile;

	static {
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
		log.info("Encrypter initial");
	}

	public Encrypter() {

	}

	public void setInputFile(String inputFile) {
		this.inputFile = inputFile;
	}

	public void setOutputFile(String outputFile) {
		this.outputFile = outputFile;
	}

	public void setCertificateFile(String certificateFile) {
		this.certificateFile = certificateFile;
	}

	public String encrypt() throws Exception{

		Document import_doc = loadDocument(inputFile);
		Key symmetric_key = generateDataEncryptionKey();
		X509Certificate cert = loadCertificate();
		String algorithmURI = XMLCipher.RSA_v1dot5;

		XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
		keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());
		EncryptedKey encryptedKey = keyCipher.encryptKey(import_doc, symmetric_key);

		algorithmURI = XMLCipher.AES_128;
		XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetric_key);

		/*
		 * Setting keyinfo inside the encrypted data being prepared.
		 */
		EncryptedData encryptedData = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(import_doc);
		keyInfo.add(encryptedKey);
		encryptedData.setKeyInfo(keyInfo);

		Element rootElement = import_doc.getDocumentElement();
		xmlCipher.doFinal(import_doc, rootElement, true);
        Encrypter.outputDocToFile(import_doc, outputFile);

		return outputDocToString(import_doc);
	}
	
	public Document encrypt(Document doc) throws Exception{

		Document import_doc = doc;
		Key symmetric_key = generateDataEncryptionKey();
		X509Certificate cert = loadCertificate();
		String algorithm = XMLCipher.RSA_v1dot5;

		XMLCipher keyCipher = XMLCipher.getInstance(algorithm);
		keyCipher.init(XMLCipher.WRAP_MODE, cert.getPublicKey());
		EncryptedKey encryptedKey = keyCipher.encryptKey(import_doc, symmetric_key);

		algorithm = XMLCipher.AES_128;
		XMLCipher xmlCipher = XMLCipher.getInstance(algorithm);
		xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetric_key);

		/*
		 * Setting keyinfo inside the encrypted data being prepared.
		 */
		EncryptedData encryptedData = xmlCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(import_doc);
		keyInfo.add(encryptedKey);
		encryptedData.setKeyInfo(keyInfo);

		Element rootElement = import_doc.getDocumentElement();
		xmlCipher.doFinal(import_doc, rootElement, true);
        //Encrypter.outputDocToFile(import_doc,outputFile);
		//String encyptContent = outputDocToFile(import_doc);
		return doc;
	}

	private Key generateDataEncryptionKey() throws Exception {

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);

		return keyGenerator.generateKey();
	}

	private Document loadDocument(String xmlContent) throws Exception {
        
        FileInputStream bais = new FileInputStream(xmlContent);
		//ByteArrayInputStream bais = new ByteArrayInputStream(xmlContent.getBytes("UTF8"));
		javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
		javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
		Document document = db.parse(bais);

		return document;
	}

	private X509Certificate loadCertificate() throws Exception {

		File certFile = new File(certificateFile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(JavaUtils.getBytesFromFile(certificateFile)));
		log.debug("loaded from {}", certFile.toURI().toURL());

		return cert;
	}
	
	private X509Certificate loadCertificate(File certFile) throws Exception {

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
//		X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(JavaUtils.getBytesFromFile(certificateFile)));
		X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(certFile));
		log.debug("loaded from: {}", certFile.toURI().toURL());

		return cert;
	}

	private String outputDocToString(Document doc) throws Exception{

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        DOMSource source = new DOMSource(doc);
        transformer.transform(source, new StreamResult(bout));
        String encyptContent = bout.toString();

        return encyptContent;
	}

    private static void outputDocToFile(Document doc, String fileName) throws Exception {

        File encryptionFile = new File(fileName);
        FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(f);
        transformer.transform(source, result);

        f.close();
        log.debug("Encrypted document: {}", encryptionFile.toURI().toURL());
    }
}
