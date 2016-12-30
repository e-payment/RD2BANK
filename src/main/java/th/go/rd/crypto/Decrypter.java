package th.go.rd.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.security.Key;
import java.security.KeyStore;
import java.security.Security;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.utils.EncryptionConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Decrypter {

	private static final Logger log = LoggerFactory.getLogger(Decrypter.class);

    private String keystoreType = "PKCS12";
    private String keystoreFile;
    private String keystorePass;
    private String keyAlias;
    private String inputFile;
	private String outputFile;

    static {
		Security.addProvider(new BouncyCastleProvider());
		org.apache.xml.security.Init.init();
		log.info("Encrypter initial");
	}

    public Decrypter() {

    }

	// public void setKeyAlias(String keyAlias) {
	// 	this.keyAlias = keyAlias;
	// }

	public void setKeystoreFile(String keystoreFile) {
		this.keystoreFile = keystoreFile;
	}

	public void setKeystorePass(String keystorePass) {
		this.keystorePass = keystorePass;
	}

	public void setKeystoreType(String keystoreType) {
		this.keystoreType = keystoreType;
	}

	public void setInputFile(String inputFile) {
		this.inputFile = inputFile;
	}

	public void setOutputFile(String outputFile) {
		this.outputFile = outputFile;
	}

	public String decrypt() throws Exception{

		KeyStore ks = KeyStore.getInstance(keystoreType,BouncyCastleProvider.PROVIDER_NAME);
        FileInputStream fis = new FileInputStream(keystoreFile);
        ks.load(fis, keystorePass.toCharArray());
        keyAlias = ks.aliases().nextElement().toString();
		Key privateKey = ks.getKey(keyAlias, keystorePass.toCharArray());
        log.debug("keyAlias: {}", keyAlias);

		Document document = loadDocument(inputFile);
		Element encryptedDataElement = (Element) document.getElementsByTagNameNS(
				EncryptionConstants.EncryptionSpecNS,
				EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);
		xmlCipher.setKEK(privateKey);
        xmlCipher.doFinal(document, encryptedDataElement);
		outputDocToFile(document, outputFile);

		log.debug("Decrypted document: {}", outputFile);
		return outputDocToString(document);
	}
	
	public void decrypt(String inputFloder) throws Exception {

		KeyStore ks = KeyStore.getInstance(keystoreType, BouncyCastleProvider.PROVIDER_NAME);
		log.debug("get KeyStore");
        
		FileInputStream fis = new FileInputStream(keystoreFile);

		if ((new File(keystoreFile)).exists()) {
			log.debug("Have CA file at {}", keystoreFile);
		}
		else {
			log.debug("Can't Find CA file at {}", keystoreFile);
		}

        ks.load(fis, keystorePass.toCharArray());
        log.debug("Pass key.load");
        
        keyAlias = ks.aliases().nextElement().toString();
        log.debug("keyAlias: {}", keyAlias);
        log.debug("keystorePass: {}", keystorePass);
		
        Key privateKey = ks.getKey(keyAlias, keystorePass.toCharArray());                
		Document document = loadDocument(inputFile, inputFloder);
		log.debug("loadDocument({}, {})", inputFile, inputFloder);
		
		Element encryptedDataElement = (Element) document.getElementsByTagNameNS(
				EncryptionConstants.EncryptionSpecNS,
				EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

		XMLCipher xmlCipher = XMLCipher.getInstance();
		xmlCipher.init(XMLCipher.DECRYPT_MODE, null);		
		xmlCipher.setKEK(privateKey);
		
		log.debug("EncryptedKey: {}", xmlCipher.getEncryptedKey());
		log.debug("PrivateKey: {}", privateKey);		
        
		xmlCipher.doFinal(document, encryptedDataElement);        
        log.debug("Decrypted to File: {}, {}", outputFile, inputFloder);

		outputDocToFile(document, outputFile, inputFloder);
	}

	private String outputDocToString(Document doc) throws Exception{

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        DOMSource source = new DOMSource(doc);
        transformer.transform(source, new StreamResult(bout));
        String content = bout.toString();

        return content;
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
	}
	
	private static void outputDocToFile(Document doc, String fileName,String dir) throws Exception {

        File encryptionFile = new File(dir,fileName);
        FileOutputStream f = new FileOutputStream(encryptionFile);

        TransformerFactory factory = TransformerFactory.newInstance();
        Transformer transformer = factory.newTransformer();
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(f);
        transformer.transform(source, result);
        f.close();      
	}

	private static Document loadDocument(String file_name) throws Exception {

		File import_file = new File(file_name);
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document document = db.parse(import_file);

		return document;
	}
	
	private static Document loadDocument(String file_name, String inputDir) throws Exception {

		File import_file = new File(inputDir, file_name);
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document document = db.parse(import_file);
        log.debug("Document loaded from {}", import_file.toURI().toURL());

		return document;
	}    
}
