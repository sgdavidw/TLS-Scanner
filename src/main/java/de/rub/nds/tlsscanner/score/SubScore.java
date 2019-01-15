package de.rub.nds.tlsscanner.score;

import de.rub.nds.tlsscanner.report.SiteReport;
import java.util.List;

public abstract class SubScore {

    private String name;

    private double weigth;

    public SubScore(String name, double weigth) {
        this.name = name;
        this.weigth = weigth;
    }

    public abstract SubScoreReport getScore(SiteReport report);

    public abstract List<Influencer> getInfluencerList();

    public final String getName() {
        return name;
    }

    public final void setName(String name) {
        this.name = name;
    }

    public final double getWeigth() {
        return weigth;
    }

    public final void setWeigth(double weigth) {
        this.weigth = weigth;
    }
}
