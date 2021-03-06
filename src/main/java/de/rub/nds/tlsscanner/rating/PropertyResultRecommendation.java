/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.rating;

import javax.xml.bind.annotation.XmlType;

@XmlType(propOrder = {"result", "shortDescription", "handlingRecommendation", "detailedDescription"})
public class PropertyResultRecommendation {

    private TestResult result;

    private String shortDescription;

    private String handlingRecommendation;

    private String detailedDescription;

    public PropertyResultRecommendation() {

    }

    public PropertyResultRecommendation(TestResult result, String resultStatus, String handlingRecommendation) {
        this.result = result;
        this.shortDescription = resultStatus;
        this.handlingRecommendation = handlingRecommendation;
    }

    public PropertyResultRecommendation(TestResult result, String resultStatus, String handlingRecommendation,
            String detailedDescription) {
        this(result, resultStatus, handlingRecommendation);
        this.detailedDescription = detailedDescription;
    }

    public TestResult getResult() {
        return result;
    }

    public void setResult(TestResult result) {
        this.result = result;
    }

    public String getShortDescription() {
        return shortDescription;
    }

    public void setShortDescription(String shortDescription) {
        this.shortDescription = shortDescription;
    }

    public String getHandlingRecommendation() {
        return handlingRecommendation;
    }

    public void setHandlingRecommendation(String handlingRecommendation) {
        this.handlingRecommendation = handlingRecommendation;
    }

    public String getDetailedDescription() {
        return detailedDescription;
    }

    public void setDetailedDescription(String detailedDescription) {
        this.detailedDescription = detailedDescription;
    }
}
