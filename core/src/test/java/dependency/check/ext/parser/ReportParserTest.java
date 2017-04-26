/**
 *
 * Copyright to the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and limitations under the License.
 */
package dependency.check.ext.parser;

import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

public class ReportParserTest {
    private TestReportParserListener listener = new TestReportParserListener();

    @Test
    public void shouldBeAbleToParseSuppressionsAndVulnerabilties() {
        parseReport("single-vulnerability-on-multiple-dependencies-with-suppression.xml");

        listener.assertVulnerabilitiesFor("jackson-core-asl-1.9.10.jar", "CVE-2016-3720");
        listener.assertSuppressionFor("jackson-core-asl-1.9.10.jar", "CVE-2016-7051");

        listener.assertVulnerabilitiesFor("jackson-core-lgpl-1.9.13.jar", "CVE-2016-3720");
        listener.assertSuppressionFor("jackson-core-lgpl-1.9.13.jar", "CVE-2016-7051");
    }

    @Test
    public void shouldBeAbleToParseOutVulnerabilitiesOfMultipleModules() {
        parseReport("multiple-vulnerabilities-on-multiple-dependencies.xml");

        listener.assertVulnerabilitiesFor("jackson-core-asl-1.9.10.jar", "CVE-2016-7051", "CVE-2016-3720");
        listener.assertVulnerabilitiesFor("jackson-core-lgpl-1.9.13.jar", "CVE-2016-7051", "CVE-2016-3720");
    }

    @Test
    public void shouldBeAbleToParseOutVulnerabilities() {
        parseReport("multiple-vulnerabilities-on-single-dependency.xml");

        listener.assertVulnerabilitiesFor("jackson-core-asl-1.9.10.jar", "CVE-2016-7051", "CVE-2016-3720");
    }

    private void parseReport(String testFilename) {
        ReportParser parser = new ReportParser();
        try (InputStream input = Thread.currentThread().getContextClassLoader().getResourceAsStream("example-reports/" + testFilename)) {
            parser.parse(input, listener);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
