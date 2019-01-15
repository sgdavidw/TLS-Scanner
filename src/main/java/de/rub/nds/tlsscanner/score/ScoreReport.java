/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.rub.nds.tlsscanner.score;

import java.util.List;

/**
 *
 */
public class ScoreReport {

    private final Score score;
    private final List<SubScoreReport> subScoreReportList;

    private final double nummericScore;

    public ScoreReport(Score score, List<SubScoreReport> subScoreReportList, double nummericScore) {
        this.score = score;
        this.subScoreReportList = subScoreReportList;
        this.nummericScore = nummericScore;
    }

    public Score getScore() {
        return score;
    }

    public List<SubScoreReport> getSubScoreReportList() {
        return subScoreReportList;
    }

    public double getNummericScore() {
        return nummericScore;
    }

}
