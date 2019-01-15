package de.rub.nds.tlsscanner.score;

import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;

public class Score {

    private final List<SubScore> subScoreList;

    private final ScoringSystem scoringSystem;

    public Score(List<SubScore> subScoreList, ScoringSystem scoringSystem) {
        this.subScoreList = subScoreList;
        this.scoringSystem = scoringSystem;
    }

    public ScoreReport getScore(SiteReport report) {
        double score = 0;
        double scoreWeigth = 0;
        Double globalLimit = null;
        List<SubScoreReport> subScoreReportList = new LinkedList<>();

        for (SubScore subScore : subScoreList) {
            SubScoreReport subScoreReport = subScore.getScore(report);
            subScoreReportList.add(subScoreReport);
            score += (subScore.getScore(report).getScore() * subScore.getWeigth());
            scoreWeigth += subScore.getWeigth();
            if (subScoreReport.isLimitsGlobalScore()) {
                if (globalLimit != null) {
                    if (globalLimit > subScoreReport.getGlobalScoreLimit()) {
                        globalLimit = subScoreReport.getGlobalScoreLimit();
                    }
                } else {
                    globalLimit = subScoreReport.getGlobalScoreLimit();
                }
            }
        }
        if (scoreWeigth != 0) {
            score = score / scoreWeigth;
        }
        if (scoringSystem.isLimitingMaxScore() && score >= scoringSystem.getMaximumScore()) {
            score = scoringSystem.getMaximumScore();
        }
        if (scoringSystem.isLimitingMinimumScore() && score <= scoringSystem.getMinimumScore()) {
            score = scoringSystem.getMinimumScore();
        }
        if (score > globalLimit) {
            score = globalLimit;
        }
        return new ScoreReport(this, subScoreReportList, score);
    }

    public List<Influencer> getInfluencerList() {
        List<Influencer> influencerList = new LinkedList<>();
        for (SubScore subScore : subScoreList) {
            influencerList.addAll(subScore.getInfluencerList());
        }
        return influencerList;
    }
}
