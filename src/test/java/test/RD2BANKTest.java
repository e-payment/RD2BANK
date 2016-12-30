package test;

import java.io.File;
import th.go.rd.crypto.*;
import util.*;

import org.junit.Test;
import org.junit.Ignore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RD2BANKTest {

	private static final Logger log = LoggerFactory.getLogger(RD2BANKTest.class);

	private String getFullPath(String relativePath) throws Exception {
		return new File(relativePath).getCanonicalPath();
	}

	@Test
	public void shouldValidFile() throws Exception {

		String xmlFile = getFullPath("./xml/rd2bank/source_xml/RD2BANK-BAYB000566729-20151215081633.xml");
		log.info("\n>>> xmlFile: {} => exists: {}", xmlFile, (new File(xmlFile)).exists());
	}

	@Test
	//@Ignore
	public void shouldEncrypt() throws Exception {

		Encrypter encrypter = new Encrypter();
		encrypter.setCertificateFile("./key/rd2bank.cer");
		encrypter.setInputFile("./xml/rd2bank/source_xml/RD2BANK-BAYB000566729-20151215081633.xml");

		String outputFile = getFullPath("./xml/rd2bank/encrypt/test.xml");
		encrypter.setOutputFile(outputFile);
		String encryptedData = encrypter.encrypt();
		log.info("encryptedData:\n{}", XmlUtil.format(encryptedData));
		log.info("\n\n>>> OutputFile: {}\n", getFullPath(outputFile));
	}

	@Test
	//@Ignore
	public void shouldDecrypt() throws Exception {

		Decrypter decrypter = new Decrypter();
		// decrypter.setKeystoreType("PKCS12");
		decrypter.setKeystoreFile("./key/rd2bank.p12");
		decrypter.setKeystorePass("P@ssw0rd");

		String outputFile = getFullPath("./xml/rd2bank/decrypt/test.xml");
		decrypter.setInputFile(getFullPath("./xml/rd2bank/encrypt/test.xml"));
		decrypter.setOutputFile(outputFile);
		String decryptedData = decrypter.decrypt();
		log.info("decryptedData:\n{}", XmlUtil.format(decryptedData));
		log.info("\n\n>>> OutputFile: {}\n", getFullPath(outputFile));
	}
}
