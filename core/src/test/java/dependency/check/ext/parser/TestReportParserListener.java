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

import org.junit.Assert;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class TestReportParserListener implements ReportParserListener {
    private HashMap<String, List<String>> filenameToVulnerabilites = new HashMap<>();
    private HashMap<String, List<String>> filenameToSuppressions = new HashMap<>();

    public void assertVulnerabilitiesFor(String dependencyFilename, String... expectedVulnerabilities) {
        Assert.assertTrue("Filename (" + dependencyFilename + ") has no vulnerabilities. Available filenames with vulnerabilites: " + filenameToVulnerabilites.keySet(),
                filenameToVulnerabilites.containsKey(dependencyFilename));

        List<String> vulnerabilities = filenameToVulnerabilites.getOrDefault(dependencyFilename, Collections.emptyList());
        Assert.assertEquals("Bad vulnerabilities for: " + dependencyFilename, Arrays.asList(expectedVulnerabilities), vulnerabilities);
    }

    public void assertSuppressionFor(String dependencyFilename, String... expectedSuppressedVulnerabilites) {
        Assert.assertTrue("Filename (" + dependencyFilename + ") has no suppressions. Available filenames with suppressions: " + filenameToSuppressions.keySet(),
                filenameToSuppressions.containsKey(dependencyFilename));

        List<String> supressions = filenameToSuppressions.getOrDefault(dependencyFilename, Collections.emptyList());
        Assert.assertEquals("Bad suppressions for: " + dependencyFilename, Arrays.asList(expectedSuppressedVulnerabilites), supressions);
    }

    @Override
    public void onVulnerability(String filename, String vulnerabilityName) {
        if (!filenameToVulnerabilites.containsKey(filename)) {
            filenameToVulnerabilites.put(filename, new ArrayList<>());
        }
        filenameToVulnerabilites.get(filename).add(vulnerabilityName);
    }

    @Override
    public void onSuppression(String filename, String vulnerabilityName) {
        if (!filenameToSuppressions.containsKey(filename)) {
            filenameToSuppressions.put(filename, new ArrayList<>());
        }
        filenameToSuppressions.get(filename).add(vulnerabilityName);
    }
}
