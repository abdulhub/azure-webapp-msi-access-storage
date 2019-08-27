package com.springprojects.azure.springazurestorage;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;

import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class WebController {

	/***
	 * Reads the blob data. Deploy the application in Azure. Make the application as
	 * Managed Service Identity (MSI). Assign Reader role to Storage Account. Assign
	 * Storage Blob Data Reader Role to the container
	 */

	@Value("${MSI_ENDPOINT}")
	private String MSIENDPOINT;

	@Value("${MSI_SECRET}")
	private String MSISECRET;

	private HttpURLConnection connection;

	private static org.apache.logging.log4j.Logger logger = LogManager.getLogger();

	private String $apiVersion = "2017-09-01";
	private String $resourceURI = "https://msistoragedemo.blob.core.windows.net";
	private String $tokenResponse;

	@GetMapping(value = "/token")
	public String getAuthToken() throws MalformedURLException, IOException {
		String $tokenAuthURI = MSIENDPOINT + "?" + "resource" + "=" + $resourceURI + "&" + "api-version" + "="
				+ $apiVersion;

		this.connection = (HttpURLConnection) (new URL($tokenAuthURI)).openConnection();
		this.connection.setRequestProperty("Secret", MSISECRET);
		this.connection.setRequestMethod("GET");
		this.connection.connect();
		$tokenResponse = readResponse(connection);
		logger.info($tokenResponse);
		return $tokenResponse;

	}

	@GetMapping(path = "/{account}/{container}/{blob}")
	public String readBlob(@PathVariable("account") String account, @PathVariable("container") String container,
			@PathVariable("blob") String fileName) throws MalformedURLException, IOException {

		String response = getToken(account);
		ObjectMapper mapper = new ObjectMapper();
		JsonNode actualObj = mapper.readTree(response);
		String access_token = actualObj.get("access_token").textValue();
		String token_type = actualObj.get("token_type").textValue();
		String resource = actualObj.get("resource").textValue();
		/** For GSON **/
		/*
		 * JSONObject jsonObj = null; jsonObj = new JSONObject(response); String
		 * access_token = jsonObj.getString("access_token"); String token_type =
		 * jsonObj.getString("token_type"); String resource =
		 * jsonObj.getString("resource");
		 */
		String data = getData(access_token, token_type, resource, container, fileName);
		return data;

	}

	private String getData(String access_token, String token_type, String resource, String container, String fileName)
			throws IOException {
		logger.info("access_token:: " + access_token);
		logger.info("token_type:: " + token_type);
		logger.info("resource:: " + resource);
		// https://msistoragedemo.blob.core.windows.net/msistorageblobs/parameters.json
		String urlString = resource + "/" + container + "/" + fileName;
		String authToken = token_type.trim() + " " + access_token;
		URL urlObj = new URL(urlString);
		HttpURLConnection httpURLConnection = (HttpURLConnection) urlObj.openConnection();
		httpURLConnection.setRequestProperty("Authorization", authToken);
		httpURLConnection.setRequestProperty("x-ms-version", "2017-11-09");
		httpURLConnection.setRequestMethod("GET");
		httpURLConnection.connect();
		String response = readResponse(httpURLConnection);
		logger.info("data retrived: " + response);
		return response;

	}

	public String getToken(String account) throws MalformedURLException, IOException {
		String $tokenAuthURI = MSIENDPOINT + "?" + "resource" + "=" + $resourceURI + "&" + "api-version" + "="
				+ $apiVersion;
		$resourceURI = "https://" + account + ".blob.core.windows.net";
		this.connection = (HttpURLConnection) (new URL($tokenAuthURI)).openConnection();
		this.connection.setRequestProperty("Secret", MSISECRET);
		this.connection.setRequestMethod("GET");
		this.connection.connect();
		$tokenResponse = readResponse(connection);
		logger.info($tokenResponse);
		return $tokenResponse;

	}

	@GetMapping(value = "/createtoken")
	public ResponseEntity<String> createToken() {

		String $tokenAuthURI = MSIENDPOINT + "?" + "resource" + "=" + $resourceURI + "&" + "api-version" + "="
				+ $apiVersion;

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.set("Secret", "MSISECRET");
		headers.setAccept(Arrays.asList(new MediaType[] { MediaType.APPLICATION_JSON }));
		HttpEntity<String> entity = new HttpEntity<String>(headers);
		ResponseEntity<String> result = restTemplate.exchange($tokenAuthURI, HttpMethod.GET, entity, String.class);

		logger.info("tokenresponse: " + result);
		return result;
	}

	private String readResponse(HttpURLConnection connection) throws IOException {
		BufferedReader bufferedReader = null;
		if (connection.getResponseCode() != 200) {
			bufferedReader = new BufferedReader(new InputStreamReader((connection.getErrorStream())));
		} else {
			bufferedReader = new BufferedReader(new InputStreamReader((connection.getInputStream())));
		}
		return readContent(bufferedReader);
	}

	public String readContent(BufferedReader reader) {
		return reader.lines().collect(Collectors.joining(System.lineSeparator()));
	}

}
