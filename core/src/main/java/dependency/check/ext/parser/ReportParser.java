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

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import static javax.xml.xpath.XPathConstants.NODESET;
import static javax.xml.xpath.XPathConstants.STRING;

public class ReportParser {
    private XPathExpression suppressedVulnerabilityExpression;
    private XPathExpression filenameTextExpression;
    private XPathExpression dependencyExpression;
    private DocumentBuilder documentBuilder;
    private XPathExpression nameTextExpression;
    private XPathExpression vulnerabilityExpression;

    public ReportParser() {
        try {
            XPathFactory xPathfactory = XPathFactory.newInstance();
            XPath xpath = xPathfactory.newXPath();

            dependencyExpression = xpath.compile("//dependency");
            vulnerabilityExpression = xpath.compile("vulnerabilities/vulnerability");
            suppressedVulnerabilityExpression = xpath.compile("vulnerabilities/suppressedVulnerability");
            nameTextExpression = xpath.compile("name/text()");
            filenameTextExpression = xpath.compile("fileName/text()");
        } catch (XPathExpressionException e) {
            throw new ReportParserException("A problem occurred when trying to initialize the xpath queries", e);
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            documentBuilder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new ReportParserException("A problem occurred when trying to initialize the document builder", e);
        }

    }

    public void parse(File reportFile, ReportParserListener listener) {
        try (InputStream input = new BufferedInputStream(new FileInputStream(reportFile))) {
            parse(input, listener);
        } catch (IOException e) {
            throw new ReportParserException("A problem occurred while parsing the report", e);
        }
    }

    public void parse(InputStream input, ReportParserListener listener) {
        try {
            Document doc = documentBuilder.parse(input);

            NodeList dependencyNodes = (NodeList) dependencyExpression.evaluate(doc, NODESET);
            for (int i = 0; i < dependencyNodes.getLength(); i++) {
                Node dependencyNode = dependencyNodes.item(i);
                String filename = (String) filenameTextExpression.evaluate(dependencyNode, STRING);

                processVulnerabilities(filename, dependencyNode, listener);
                processSuppressions(filename, dependencyNode, listener);
            }

        } catch (SAXException | IOException | XPathExpressionException e) {
            throw new ReportParserException("A problem occurred when parsing the report file", e);
        }

    }

    private void processSuppressions(String filename, Node dependencyNode, ReportParserListener listener) throws XPathExpressionException {
        NodeList vulnerabilities = (NodeList) suppressedVulnerabilityExpression.evaluate(dependencyNode, NODESET);
        for (int j = 0; j < vulnerabilities.getLength(); j++) {
            Node vulnerability = vulnerabilities.item(j);

            String vulnerabilityName = (String) nameTextExpression.evaluate(vulnerability, STRING);
            listener.onSuppression(filename, vulnerabilityName);
        }
    }

    private void processVulnerabilities(String filename, Node dependencyNode, ReportParserListener listener) throws XPathExpressionException {
        NodeList vulnerabilities = (NodeList) vulnerabilityExpression.evaluate(dependencyNode, NODESET);
        for (int j = 0; j < vulnerabilities.getLength(); j++) {
            Node vulnerability = vulnerabilities.item(j);

            String vulnerabilityName = (String) nameTextExpression.evaluate(vulnerability, STRING);
            listener.onVulnerability(filename, vulnerabilityName);
        }
    }
}
