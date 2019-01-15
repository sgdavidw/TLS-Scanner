package de.rub.nds.tlsscanner.score;

import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class GenericSubScore extends SubScore {

    private List<Influencer> influencerList;

    public GenericSubScore(String name, double weigth, List<Influencer> influencerList) {
        super(name, weigth);
        this.influencerList = influencerList;
    }

    @Override
    public SubScoreReport getScore(SiteReport report) {
        List<Influencer> relevantInfluencer = new LinkedList<>();
        double weigth = 0;
        double score = 0;
        Double globalLimit = null;
        for (Influencer influencer : influencerList) {
            if (influencer.isRelevantFor(report)) {
                relevantInfluencer.add(influencer);
                score += (influencer.getValue() * influencer.getWeigth());
                weigth += influencer.getWeigth();
                if (influencer.isGlobalLimiting()) {
                    if (globalLimit == null) {
                        globalLimit = influencer.getGlobalLimit();
                    } else {
                        if (globalLimit > influencer.getGlobalLimit()) {
                            globalLimit = influencer.getGlobalLimit();
                        }
                    }
                }
            }
        }
        if (weigth == 0) {
            weigth = 1;
        }
        return new SubScoreReport(this, relevantInfluencer, score / weigth, globalLimit);
    }

    @Override
    public List<Influencer> getInfluencerList() {
        return influencerList;
    }
}
