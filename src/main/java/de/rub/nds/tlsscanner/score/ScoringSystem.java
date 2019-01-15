package de.rub.nds.tlsscanner.score;

/**
 *
 */
public class ScoringSystem {

    private Long minimumScore;

    private Long maximumScore;

    public ScoringSystem(Long minimumScore, Long maximumScore) {
        this.minimumScore = minimumScore;
        this.maximumScore = maximumScore;
    }

    public boolean isLimitingMaxScore() {
        return maximumScore == null;
    }

    public boolean isLimitingMinimumScore() {
        return minimumScore == null;
    }

    public Long getMinimumScore() {
        return minimumScore;
    }

    public void setMinimumScore(Long minimumScore) {
        this.minimumScore = minimumScore;
    }

    public Long getMaximumScore() {
        return maximumScore;
    }

    public void setMaximumScore(Long maximumScore) {
        this.maximumScore = maximumScore;
    }

}
