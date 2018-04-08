package ZAP;

import org.testng.annotations.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.Proxy;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.CapabilityType;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.testng.annotations.Test;

public class TestPointAttack {
	@Test
	public void Test1() {
		WebDriver driver1;
		System.setProperty("webdriver.chrome.driver", "C:\\SELENIUM\\Chrome\\chromedriver.exe");
		Proxy proxy = new Proxy();
		proxy.setHttpProxy("localhost:8090");
		proxy.setFtpProxy("localhost:8090");
		proxy.setSslProxy("localhost:8090");
		DesiredCapabilities capabilities = new DesiredCapabilities();
		capabilities.setCapability(CapabilityType.PROXY, proxy);
		driver1 = new ChromeDriver(capabilities);
		driver1.get("https://www.testpoint.com.au/");
		driver1.findElement(By.xpath("//a[@href='https://www.testpoint.com.au/contact-us/']")).click();
		driver1.close();
	}
}
