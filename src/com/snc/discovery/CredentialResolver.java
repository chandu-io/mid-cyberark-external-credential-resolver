package com.snc.discovery;

import static com.service_now.mid.services.CredentialResolverProxy.ATTR_NAME_AZURE_AUTH_METHOD;
import static com.service_now.mid.util.CloudServiceAccountCredentialUtil.AWS_SECRET_KEY__ATTR_NAME;
import static com.service_now.mid.util.CloudServiceAccountCredentialUtil.AZURE_CERTIFICATE_ALIAS_ATTR_NAME;
import static com.service_now.mid.util.CloudServiceAccountCredentialUtil.AZURE_CERTIFICATE_ATTR_NAME;
import static com.service_now.mid.util.CloudServiceAccountCredentialUtil.AZURE_CERTIFICATE_PASSPHRASE_ATTR_NAME;
import static com.service_now.mid.util.CloudServiceAccountCredentialUtil.AZURE_CLIENT_ID_ATTR_NAME;
import static com.service_now.mid.util.CloudServiceAccountCredentialUtil.AZURE_TENANT_ID_ATTR_NAME;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import com.service_now.mid.services.Config;
import com.snc.automation_common.integration.creds.IExternalCredential;
import com.snc.core_automation_common.logging.Logger;
import com.snc.core_automation_common.logging.LoggerFactory;

/**
 * Basic implementation of a CredentialResolver that uses the JavaPasswordSDK API to connect to CyberArk vault.
 */
public class CredentialResolver implements IExternalCredential {

	// Required parameters that must be in the config file in order to use CyberArk.
	// Parameters used to access the vault / credentials
	public static final String SAFE_FOLDER_PROPERTY = "mid.ext.cred.cyberark.safe_folder";
	public static final String SAFE_NAME_PROPERTY = "mid.ext.cred.cyberark.safe_name";
	public static final String SAFE_USER_APP_ID_PROPERTY = "mid.ext.cred.cyberark.app_id";
	public static final String SAFE_TIMEOUT_PROPERTY = "mid.ext.cred.cyberark.safe_timeout";
	public static final String CYBERARK_INCLUDE_DOMAIN_PROPERTY = "mid.ext.cred.cyberark.include_basic_auth_domain";

	private static final String DEFAULT_SAFE_APP_ID = "ServiceNow_MID_Server";
	private static final String DEFAULT_SAFE_TIMEOUT = "10";
	private static final String DEF_SAFE_CREDID_SPLIT = ":";

	// ===  Load below parameters from MID config parameters.  === //

	// The Safe folder to use as specified in the MID config.xml file (must match folder name in CyberArk)
	private String safeFolder;

	// The Safe name to use as specified in the MID config.xml file (must match safe name in CyberArk)
	private String safeName;

	// The App-ID used when connecting to CyberArk (can be overridden in the config.xml file)
	private String safeAppID;

	// The vault (server) response timeout in seconds to use as specified in the MID config.xml file
	private String safeTimeout;

	// === === === === === === === === === === === === === === === //

	private String includeDomain;

	// Logger object to log messages in agent.log
	private static final Logger fLogger = LoggerFactory.getLogger(CredentialResolver.class);

	public CredentialResolver() {
		this.safeAppID = Config.get().getProperty(SAFE_USER_APP_ID_PROPERTY);
		if (isNullOrEmpty(this.safeAppID)) {
			this.safeAppID = "ServiceNow_MID_Server";
		}
		this.safeTimeout = Config.get().getProperty(SAFE_TIMEOUT_PROPERTY);
		if (isNullOrEmpty(this.safeTimeout)) {
			this.safeTimeout = "10";
		}
		this.includeDomain = Config.get().getProperty(CYBERARK_INCLUDE_DOMAIN_PROPERTY);
		if (isNullOrEmpty(this.includeDomain)) {
			this.includeDomain = "false";
		}
		this.safeFolder = Config.get().getProperty(SAFE_FOLDER_PROPERTY);
		if (isNullOrEmpty(this.safeFolder)) {
			fLogger.error("[Vault] INFO - CyberArkCredentialResolver safeFolder not set!");
		}
		this.safeName = Config.get().getProperty(SAFE_NAME_PROPERTY);
		if (isNullOrEmpty(this.safeName)) {
			fLogger.error("[Vault] INFO - CyberArkCredentialResolver safeSafeName not set!");
		}
	}

	/**
	 * Return the API version supported by this class.
	 * Note: should be less than 1.1 for external credential resolver.
	 */
	@Override
	public String getVersion() {
		return "0.1";
	}


	/**
	 * Config method with preloaded config parameters from config.xml.
	 *
	 * @param configMap - contains config parameters with prefix "mid.ext.cred" only.
	 */
	@Override
	public void config(Map<String, String> configMap) {
		// Note: To load config parameters from MID config.xml if not available in configMap.
		// propValue = Config.get().getProperty("<Parameter Name>")

		safeAppID = configMap.get(SAFE_USER_APP_ID_PROPERTY);
		if (isNullOrEmpty(safeAppID)) {
			// use default AppId
			safeAppID = DEFAULT_SAFE_APP_ID;
		}

		fLogger.info("SafeAppID: " + safeAppID);

		safeTimeout = configMap.get(SAFE_TIMEOUT_PROPERTY);
		if (isNullOrEmpty(safeTimeout)) {
			// use default timeout
			safeTimeout = DEFAULT_SAFE_TIMEOUT;
		}

		fLogger.info("safeTimeout: " + safeTimeout);

		includeDomain = configMap.get(CYBERARK_INCLUDE_DOMAIN_PROPERTY);
		if (isNullOrEmpty(includeDomain)) {
			// include domain for windows username by default.
			includeDomain = "false";
		}

		fLogger.info("includeDomain: " + includeDomain);

		safeFolder = configMap.get(SAFE_FOLDER_PROPERTY);

		fLogger.info("safeFolder: " + safeFolder);

		if (isNullOrEmpty(safeFolder)) {
			fLogger.error("[Vault] INFO - CredentialResolver safeFolder not set!");
		}

		safeName = configMap.get(SAFE_NAME_PROPERTY);

		fLogger.info("safeName: " + safeName);

		if (isNullOrEmpty(safeName)) {
			fLogger.error("[Vault] INFO - CredentialResolver safeSafeName not set!");
		}
	}

	/**
	 * Resolve a credential.
	 */
	@Override
	public Map<String, String> resolve(Map<String, String> args) {

		String credId = args.get(ARG_ID);
		String credType = args.get(ARG_TYPE);

		if (isNullOrEmpty(credId) || isNullOrEmpty(credType)) {
			throw new RuntimeException("Invalid credential Id or type found.");
		}

		String policyId = "";

		// the resolved credential is returned in a HashMap...
		Map<String, String> result = new HashMap<>();

		try {
			// get safeName and policyId from credId if exists.
			String[] parts = credId.split(Pattern.quote(DEF_SAFE_CREDID_SPLIT), -1);
			if (parts.length == 1) {
				credId = parts[0];
			} else if (parts.length == 2) {
				// Ignore safe name field of credId if empty
				if (!parts[0].isEmpty()) {
					safeName = parts[0];
				}
				credId = parts[1];
			} else if (parts.length == 3) {
				// Ignore safe name field of credId if empty
				if (!parts[0].isEmpty()) {
					safeName = parts[0];
				}
				credId = parts[1];
				policyId = parts[2];
			} else {
				throw new RuntimeException("Invalid Credential ID: Credential Id has split string more than twice");
			}

			fLogger.info("credId: " + credId);
			fLogger.info("credType: " + credType);
			fLogger.info("policyId: " + policyId);

			if ("azure".equals(credType)) {
				// tenant_id, client_id, auth_method, secret_key, certificate, cert_passphrase, cert_alias
				final String prefix = "mid.ct.ext.cred.resolver.";
				result.put(AZURE_TENANT_ID_ATTR_NAME,
						Config.get().getProperty(prefix + AZURE_TENANT_ID_ATTR_NAME));
				result.put(AZURE_CLIENT_ID_ATTR_NAME,
						Config.get().getProperty(prefix + AZURE_CLIENT_ID_ATTR_NAME));
				result.put(ATTR_NAME_AZURE_AUTH_METHOD,
						Config.get().getProperty(prefix + ATTR_NAME_AZURE_AUTH_METHOD));
				result.put(AWS_SECRET_KEY__ATTR_NAME,
						Config.get().getProperty(prefix + AWS_SECRET_KEY__ATTR_NAME));
				result.put(AZURE_CERTIFICATE_ATTR_NAME,
						Config.get().getProperty(prefix + AZURE_CERTIFICATE_ATTR_NAME));
				result.put(AZURE_CERTIFICATE_PASSPHRASE_ATTR_NAME,
						Config.get().getProperty(prefix + AZURE_CERTIFICATE_PASSPHRASE_ATTR_NAME));
				result.put(AZURE_CERTIFICATE_ALIAS_ATTR_NAME,
						Config.get().getProperty(prefix + AZURE_CERTIFICATE_ALIAS_ATTR_NAME));
			} else {
				fLogger.error("[Vault] INFO - CredentialResolver - invalid credential type found.");
			}
		} catch (Exception e) {
			// Catch block
			fLogger.error("### Unable to find credential from CyberArk server.", e);
		}

		return result;
	}

	private String formatObjQuery(String credId, String safeName, String safeFolder, String policyId) {
		return "safe=" + safeName + ";folder=" + safeFolder + ";object=" + credId +
				(isNullOrEmpty(policyId) ? "" : ";policyid=" + policyId);
	}

	private static boolean isNullOrEmpty(String str) {
		if (str != null && !str.trim().isEmpty()) {
			return false;
		}
		return true;
	}

}
