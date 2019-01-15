package de.rub.nds.tlsscanner.score;

import de.rub.nds.tlsscanner.report.SiteReport;

/**
 *
 */
public abstract class Influencer {

    private final String name;

    private final String description;

    private final String recommendation;

    public Influencer(String name, String description, String recommendation) {
        this.name = name;
        this.description = description;
        this.recommendation = recommendation;
    }

    public abstract Double getValue();

    public abstract Double getWeigth();

    public abstract boolean isGlobalLimiting();

    public abstract Double getGlobalLimit();

    public abstract boolean isRelevantFor(SiteReport report);

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    public String getRecommendation() {
        return recommendation;
    }

}
