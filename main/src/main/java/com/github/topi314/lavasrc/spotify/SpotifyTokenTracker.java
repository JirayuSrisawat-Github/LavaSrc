package com.github.topi314.lavasrc.spotify;

import com.github.topi314.lavasrc.LavaSrcTools;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.message.BasicNameValuePair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

public class SpotifyTokenTracker {
	private static final Logger log = LoggerFactory.getLogger(SpotifyTokenTracker.class);
	private static final int[] SECRET_ARRAY = {66, 77, 22, 66, 22, 86, 33, 88, 44, 88, 33, 78, 78, 11, 23, 76, 23};

	private static final String BASE_URL = "https://open.spotify.com/get_access_token";
	private static final String REASON_PARAM = "init";
	private static final String PRODUCT_TYPE_PARAM = "web-player";
	private static final String TOTP_VERSION = "5";
	private static final String URL_FORMAT = "%s?reason=%s&productType=%s&totp=%s&totpVer=%s&ts=%d";

	private final SpotifySourceManager sourceManager;
	private final String clientId;
	private final String clientSecret;

	private String accessToken;
	private Instant expires;

	public SpotifyTokenTracker(SpotifySourceManager source, String clientId, String clientSecret) {
		this.sourceManager = source;
		this.clientId = clientId;
		this.clientSecret = clientSecret;

		if (!hasValidCredentials()) {
			log.info("Missing/invalid credentials, falling back to public token.");
		}
	}

	public String getAccessToken() {
		if (accessToken == null || expires == null || expires.isBefore(Instant.now())) {
			synchronized (this) {
				if (accessToken == null || expires == null || expires.isBefore(Instant.now())) {
					refreshAccessToken();
				}
			}
		}

		return accessToken;
	}

	private void refreshAccessToken() {
		boolean usePublicToken = !hasValidCredentials();
		HttpUriRequest request;

		if (!usePublicToken) {
			request = new HttpPost("https://accounts.spotify.com/api/token");
			request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString((this.clientId + ":" + this.clientSecret).getBytes(StandardCharsets.UTF_8)));
			((HttpPost) request).setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("grant_type", "client_credentials")), StandardCharsets.UTF_8));
		} else {
			try {
				SecretGenerator secretGen = new SecretGenerator(SECRET_ARRAY);
				String secretBase32 = secretGen.getSecret();

				long timestamp = System.currentTimeMillis();

				TOTPGenerator totpGen = new TOTPGenerator(secretBase32);
				String totp = totpGen.generateTOTP(timestamp, 1);

				log.debug("Generated TOTP: {}", totp);

				String accessTokenUrl = String.format(
					URL_FORMAT,
					BASE_URL,
					REASON_PARAM,
					PRODUCT_TYPE_PARAM,
					totp,
					TOTP_VERSION,
					timestamp
				);

				log.debug("Access token URL: {}", accessTokenUrl);
				request = new HttpGet(accessTokenUrl);
			} catch (Exception e) {
				log.warn("TOTP generation failed, falling back to basic token URL", e);
				request = new HttpGet(BASE_URL);
			}
		}

		try {
			var json = LavaSrcTools.fetchResponseAsJson(sourceManager.getHttpInterface(), request);

			if (!json.get("error").isNull()) {
				String error = json.get("error").text();
				throw new RuntimeException(error);
			}

			if (!usePublicToken) {
				accessToken = json.get("access_token").text();
				expires = Instant.now().plusSeconds(json.get("expires_in").asLong(0));
			} else {
				accessToken = json.get("accessToken").text();
				expires = Instant.ofEpochMilli(json.get("accessTokenExpirationTimestampMs").asLong(0));
			}

			log.debug("Successfully obtained Spotify {} token, expires: {}",
				usePublicToken ? "public" : "client credentials", expires);
		} catch (IOException e) {
			throw new RuntimeException("Access token refreshing failed", e);
		}
	}

	private boolean hasValidCredentials() {
		return clientId != null && !clientId.isEmpty() && clientSecret != null && !clientSecret.isEmpty();
	}

	private static class SecretGenerator {
		private final int[] array;
		private final String secretBase32;

		public SecretGenerator(int[] array) {
			this.array = array;
			this.secretBase32 = generateSecretFromArray();
		}

		private String generateSecretFromArray() {
			byte[] secretBytes = new byte[array.length];
			for (int i = 0; i < array.length; i++) {
				secretBytes[i] = (byte)(array[i] ^ ((i % 33) + 9));
			}
			return bufferToBase32(secretBytes);
		}

		private String bufferToBase32(byte[] buffer) {
			final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
			StringBuilder bits = new StringBuilder();
			StringBuilder base32 = new StringBuilder();

			for (byte b : buffer) {
				String byteStr = Integer.toBinaryString(b & 0xFF);
				bits.append("0".repeat(8 - byteStr.length())).append(byteStr);
			}

			for (int i = 0; i < bits.length(); i += 5) {
				String chunk = bits.substring(i, Math.min(i + 5, bits.length()));
				while (chunk.length() < 5) {
					chunk += "0";
				}
				base32.append(alphabet.charAt(Integer.parseInt(chunk, 2)));
			}

			return base32.toString();
		}

		public String getSecret() {
			return secretBase32;
		}
	}

	private static class TOTPGenerator {
		private final byte[] secret;
		private final String algorithm;
		private final int digits;
		private final int period;

		public TOTPGenerator(String secret) {
			this(secret, "SHA256", 6, 30);
		}

		public TOTPGenerator(String secret, String algorithm, int digits, int period) {
			this.secret = base32ToBuffer(secret);
			this.algorithm = algorithm;
			this.digits = digits;
			this.period = period;
		}

		private byte[] base32ToBuffer(String base32) {
			final String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
			StringBuilder bits = new StringBuilder();
			StringBuilder buffer = new StringBuilder();

			base32 = base32.replaceAll("=+$", "");

			for (int i = 0; i < base32.length(); i++) {
				int val = alphabet.indexOf(Character.toUpperCase(base32.charAt(i)));
				if (val == -1) throw new IllegalArgumentException("Invalid Base32 character");

				String valBits = Integer.toBinaryString(val);
				while (valBits.length() < 5) {
					valBits = "0" + valBits;
				}
				bits.append(valBits);
			}

			for (int i = 0; i + 8 <= bits.length(); i += 8) {
				String byteStr = bits.substring(i, i + 8);
				int byteVal = Integer.parseInt(byteStr, 2);
				buffer.append((char)byteVal);
			}

			return buffer.toString().getBytes(StandardCharsets.ISO_8859_1);
		}

		public String generateTOTP(long timestamp, int window) {
			long counter = timestamp / 1000 / period;
			String generatedOtp = null;

			for (int i = -window; i <= window; i++) {
				generatedOtp = generateTOTPForCounter(counter + i);
				if (generatedOtp != null) return generatedOtp;
			}

			return null;
		}

		private String generateTOTPForCounter(long counter) {
			try {
				byte[] counterBuffer = new byte[8];
				for (int i = 7; i >= 0; i--) {
					counterBuffer[i] = (byte)(counter & 0xFF);
					counter >>= 8;
				}

				Mac hmac = Mac.getInstance("Hmac" + algorithm);
				SecretKeySpec keySpec = new SecretKeySpec(secret, "Hmac" + algorithm);
				hmac.init(keySpec);
				byte[] hmacResult = hmac.doFinal(counterBuffer);

				int offset = hmacResult[hmacResult.length - 1] & 0xF;
				int binary = ((hmacResult[offset] & 0x7F) << 24) |
					((hmacResult[offset + 1] & 0xFF) << 16) |
					((hmacResult[offset + 2] & 0xFF) << 8) |
					(hmacResult[offset + 3] & 0xFF);

				int power = (int)Math.pow(10, digits);
				int otp = binary % power;

				return String.format("%0" + digits + "d", otp);
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				log.error("Error generating TOTP", e);
				return null;
			}
		}
	}
}