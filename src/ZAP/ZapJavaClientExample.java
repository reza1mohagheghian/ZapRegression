package ZAP;

import org.testng.annotations.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.zaproxy.clientapi.core.Alert;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;

import testpoint.StreamTest;

public class ZapJavaClientExample {

	private static final int ZAP_PORT = 8090;
	private static final String TARGET = "http://www.testpoint.com.au/";
	private static final String RELEASE = "1.0";
	private static final String BUILD = "1.0";
	private static final String ENVIRONMENT = "www.testpoint.com.au";
	HashMap<Integer, String> alertMap = new HashMap<Integer, String>();
	HashMap<Integer, String> URLMap = new HashMap<Integer, String>();
	HashMap<Integer, String> riskMap = new HashMap<Integer, String>();
	HashMap<Integer, String> confidenceMap = new HashMap<Integer, String>();
	HashMap<Integer, String> parametersMap = new HashMap<Integer, String>();
	HashMap<Integer, String> attackMap = new HashMap<Integer, String>();
	HashMap<Integer, String> evidenceMap = new HashMap<Integer, String>();
	HashMap<Integer, Integer> cweidMap = new HashMap<Integer, Integer>();
	HashMap<Integer, Integer> wascidMap = new HashMap<Integer, Integer>();
	HashMap<Integer, String> descriptionMap = new HashMap<Integer, String>();
	HashMap<Integer, String> otherMap = new HashMap<Integer, String>();
	HashMap<Integer, String> solutionMap = new HashMap<Integer, String>();
	HashMap<Integer, String> referenceMap = new HashMap<Integer, String>();

	List<String> policies = new ArrayList<String>();
	List<Integer> idList = new ArrayList<Integer>();

	private void startZap() throws Exception {

		System.out.println("Starting ZAP...");
		// Path to zap.sh or zap.bat
		// new ProcessBuilder("C:/Program Files (x86)/OWASP/Zed Attack
		// Proxy/zap.bat", "-port " + ZAP_PORT).start();
		// Runtime rt = Runtime.getRuntime();
		// rt.exec("cmd.exe /c C:/Program Files (x86)/OWASP/Zed Attack
		// Proxy/zap.bat -port 8090");
		System.out.println("Waiting for ZAP...");
		Thread.sleep(15000);

	}

	@Test
	public void RunZap() throws Exception {
		startZap();
		FillRequirements();

		final ClientApi clientApi = new ClientApi("localhost", ZAP_PORT);

		System.out.println("Accessing Target: " + TARGET);
		clientApi.accessUrl(TARGET);

		// Start spidering the target
		System.out.println("Spider : " + TARGET);
		ApiResponse resp = clientApi.spider.scan("4nji0k2uf2qec5bop6j4oh2149", TARGET, null, null, null);
		String scanid;
		int progress;

		// The scan now returns a scan id to support concurrent scanning
		scanid = ((ApiResponseElement) resp).getValue();

		// Poll the status until it completes
		int lastProgress=0;
		while (true) {
			progress = Integer.parseInt(((ApiResponseElement) clientApi.spider.status(scanid)).getValue());
			if (progress>lastProgress) {
				System.out.println("Spider progress : " + progress + "%");
				lastProgress=progress;
			} 
			if (progress >= 20) {
				clientApi.spider.stopAllScans("4nji0k2uf2qec5bop6j4oh2149");
				break;
			}
		}
		System.out.println("Spider complete");

		// Give the passive scanner a chance to complete
		Thread.sleep(2000);

		System.out.println("Active scan : " + TARGET);
		resp = clientApi.ascan.scan("4nji0k2uf2qec5bop6j4oh2149", TARGET, "True", "False", null, null, null);

		// The scan now returns a scan id to support concurrent scanning
		scanid = ((ApiResponseElement) resp).getValue();
		resp = clientApi.ascan.scanProgress(scanid);
		// Poll the status until it completes
		lastProgress=0;
		while (true) {
			progress = Integer.parseInt(((ApiResponseElement) clientApi.ascan.status(scanid)).getValue());
			if (progress>lastProgress) {
				System.out.println("Active Scan progress : " + progress + "%");
				lastProgress=progress;
			}
			if (progress >= 100) {
				clientApi.ascan.stopAllScans("4nji0k2uf2qec5bop6j4oh2149");
				break;
			}
		}
		System.out.println("Active Scan complete");

		System.out.println("Sleep for 10 sec, to  record URL to find vulnerabilities");
		Thread.sleep(10000);
		List<Alert> alert = clientApi.getAlerts("", 0, 10000);
		int counter = 1;
		for (Iterator iterator = alert.iterator(); iterator.hasNext();) {
			Alert alert2 = (Alert) iterator.next();
			System.out.println("=================================================");
			System.out.println("Session ID: " + counter);
			idList.add(counter);
			System.out.println("Alert is: " + alert2.getAlert());
			alertMap.put(counter, alert2.getAlert());
			System.out.println("URL is: " + alert2.getUrl());
			URLMap.put(counter, alert2.getUrl());
			System.out.println("Risk is: " + alert2.getRisk());
			riskMap.put(counter, alert2.getRisk().toString());
			System.out.println("Confidence is: " + alert2.getConfidence());
			confidenceMap.put(counter, alert2.getConfidence().toString());
			System.out.println("Parameters are: " + alert2.getParam());
			parametersMap.put(counter, alert2.getParam());
			System.out.println("Attack is: " + alert2.getAttack());
			attackMap.put(counter, alert2.getAttack());
			System.out.println("Evidence is: " + alert2.getEvidence());
			evidenceMap.put(counter, alert2.getEvidence());
			System.out.println("CWE ID is: " + alert2.getCweId());
			cweidMap.put(counter, alert2.getCweId());
			System.out.println("WASC ID is: " + alert2.getWascId());
			wascidMap.put(counter, alert2.getWascId());
			System.out.println("Description is: " + alert2.getDescription());
			descriptionMap.put(counter, alert2.getDescription());
			System.out.println("Other Information is: " + alert2.getOther());
			otherMap.put(counter, alert2.getOther());
			System.out.println("Solution is: " + alert2.getSolution());
			solutionMap.put(counter, alert2.getSolution());
			System.out.println("Reference is: " + alert2.getReference());
			referenceMap.put(counter, alert2.getReference());

			counter += 1;
		}
		UpdateVansah();

		System.out.println("Shutdown ZAP.");
		// clientApi.core.shutdown("4nji0k2uf2qec5bop6j4oh2149");

	}

	private void UpdateVansah() {
		for (Iterator iterator = policies.iterator(); iterator.hasNext();) {
			boolean failed = false;
			String testedPolicy = "";
			String policy = (String) iterator.next();
			for (Iterator iterator2 = alertMap.values().iterator(); iterator2.hasNext();) {
				testedPolicy = (String) iterator2.next();
				if (policy.equals(testedPolicy)) {
					failed = true;
					break;
				} else {
					failed = false;
				}
			}
			if (failed) {
				updateFailVansah(policy);
			} else {
				updatePassVansah(policy);
			}
		}
	}

	private void updateFailVansah(String testedPolicy) {
		List<Integer> idLists = new ArrayList<Integer>();
		for (Iterator iterator = idList.iterator(); iterator.hasNext();) {
			Integer integer = (Integer) iterator.next();
			if (alertMap.get(integer).equals(testedPolicy)) {
				idLists.add(integer);
			}
		}
		for (Iterator iterator = idLists.iterator(); iterator.hasNext();) {
			Integer integer = (Integer) iterator.next();
			StreamTest ST1 = new StreamTest();
			String comment="Session ID: " + integer + " | " + "URL is: "
					+ nullChecker(URLMap.get(integer)) + " | " + "Risk is: " + nullChecker(riskMap.get(integer)) + " | "
					+ "Confidence is: " + nullChecker(confidenceMap.get(integer)) + " | " + "Parameters are: "
					+ nullChecker(parametersMap.get(integer)) + " | " + "Attack is: " + nullChecker(attackMap.get(integer)) + " | "
					+ "Evidence is: " + nullChecker(evidenceMap.get(integer)) + " | " + "Description is: "
					+ nullChecker(descriptionMap.get(integer)) + " | " + "Other Information is: " + nullChecker(otherMap.get(integer))
					+ " | " + "Solution is: " + nullChecker(solutionMap.get(integer)) + " | " + "Reference is: " + nullChecker(referenceMap.get(integer));
			System.out.println(comment);
			ST1.sendUpdateLog("SecurityPackage", testedPolicy, nullChecker(alertMap.get(integer)), RELEASE, BUILD, ENVIRONMENT,"fail",comment,"");
		}
	}

	private String nullChecker(String string) {
//		System.out.println("response: "+string);
		if (string.equals("")) {
			return "N/A";
		} else {
			return string.replaceAll("[\r\n]+", " ");
		}
	}

	private void updatePassVansah(String testedPolicy) {
		StreamTest ST1 = new StreamTest();
		ST1.sendUpdateLog("SecurityPackage", testedPolicy, testedPolicy, RELEASE, BUILD, ENVIRONMENT,
				"pass", "No Vulnerability Found!", "");
	}

	private void FillRequirements() {
		FillPolicies();
		// StreamTest ST1 = new StreamTest();
		// for (int i = 0; i < policies.size(); i++) {
		// ST1.sendUpdateLog("testPackage", policies.get(i), "Test Case:
		// "+policies.get(i), RELEASE, BUILD, ENVIRONMENT, "N/A", "", "");
		// }
	}

	private void FillPolicies() {
		// PASSIVE RULE POLICIES
		policies.add("Application Error Disclosure");
		policies.add("Content-Type Header Missing");
		policies.add("Cookie No HttpOnly Flag");
		policies.add("Cookie Without Secure Flag");
		policies.add("Cross-Domain JavaScript Source File Inclusion");
		policies.add("Incomplete or No Cache-control and Pragma HTTP Header Set");
		policies.add("Password Autocomplete in Browser");
		policies.add("Private IP Disclosure");
		policies.add("Script passive scan rules");
		policies.add("Secure Pages Include Mixed Content");
		policies.add("Session ID in URL Rewrite");
		policies.add("Stats Passive Scan Rule");
		policies.add("Web Browser XSS Protection Not Enabled");
		policies.add("X-Content-Type-Options Header Missing");
		policies.add("X-Frame-Options Header Not Set");
		// SCAN RULE POLICIES
		policies.add("Directory Browsing");
		policies.add("Buffer Overflow");
		policies.add("CRLF Injection");
		policies.add("Cross Site Scripting (Persistent)");
		policies.add("Cross Site Scripting (Persistent) - Prime");
		policies.add("Cross Site Scripting (Persistent) - Spider");
		policies.add("Cross Site Scripting (Reflected)");
		policies.add("Format String Error");
		policies.add("Parameter Tampering");
		policies.add("Remote OS Command Injection");
		policies.add("Server Side Code Injection");
		policies.add("Server Side Include");
		policies.add("SQL Injection");
		policies.add("External Redirect");
		policies.add("Script Active Scan Rules");
		policies.add("Path Traversal");
		policies.add("Remote File Inclusion");
	}
}