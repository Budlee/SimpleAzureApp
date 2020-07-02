package com.budlee.azure.clientcredentials;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Set;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientCertificate;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ClientcredentialsApplication implements CommandLineRunner {

	public static void main(String[] args) {
		SpringApplication.run(ClientcredentialsApplication.class, args);
	}

	@Value("${sample.cert.path}")
	String certPath;
	@Value("${sample.private.path}")
	String privatePath;
	@Value("${sample.clientId}")
	String clientId;
	@Value("${sample.tokenuri}")
	String tokenUri;

	@Override
	public void run(String... args) throws Exception {
		PrivateKey privateKey = createPrivateKey(privatePath);
		X509Certificate x509 = createX509(certPath);
		final IClientCertificate certificate = ClientCredentialFactory.createFromCertificate(privateKey, x509);
		final ConfidentialClientApplication clientApplication = ConfidentialClientApplication
				.builder(clientId, certificate)
				.authority(tokenUri)
				.build();

		Set<String> scopes = Collections.singleton("https://graph.microsoft.com/.default");
		final ClientCredentialParameters parameters = ClientCredentialParameters.builder(scopes).build();

		final IAuthenticationResult iAuthenticationResult = clientApplication.acquireToken(parameters).get();
		System.out.println(iAuthenticationResult);

	}

	private X509Certificate createX509(String s) throws Exception {
		InputStream inputStream = new FileInputStream(s);
		final Certificate x509 = CertificateFactory.getInstance("X.509")
				.generateCertificate(inputStream);
		return (X509Certificate) x509;
	}


	private PrivateKey createPrivateKey(String s) throws Exception {
		final byte[] bytes = Files.readAllBytes(Path.of(s));
		final PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytes);
		final PrivateKey rsa = KeyFactory.getInstance("RSA")
				.generatePrivate(pkcs8EncodedKeySpec);
		return rsa;
	}
}
