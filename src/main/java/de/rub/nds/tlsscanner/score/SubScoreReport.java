package de.rub.nds.tlsscanner.score;

import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class SubScoreReport {

    private final SubScore subScore;

    private final List<Influencer> influencerList;

    private final double score;
    
    private final Double globalLimit;

    public SubScoreReport(SubScore subScore, List<Influencer> influencerList, double score, double globalLimit) {
        this.subScore = subScore;
        this.influencerList = influencerList;
        this.score = score;
        this.globalLimit = globalLimit;
    }

    public List<Influencer> getLimitingInfluencer() {
        List<Influencer> tempInfluencerList = new LinkedList<>();
        for (Influencer influencer : influencerList) {
            if (influencer.isGlobalLimiting()) {
                tempInfluencerList.add(influencer);
            }
        }
        return tempInfluencerList;
    }

    public SubScore getSubScore() {
        return subScore;
    }

    public List<Influencer> getInfluencerList() {
        return influencerList;
    }
    
    public boolean isLimitsGlobalScore() {
        return globalLimit == null;
    }

    public Double getGlobalScoreLimit() {
        return globalLimit;
    }

    public double getScore() {
        return score;
    }
}
