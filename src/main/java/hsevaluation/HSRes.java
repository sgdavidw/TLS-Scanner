package hsevaluation;

import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import java.io.Serializable;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class HSRes implements Serializable {
    
    private String host;
    private Boolean supportsSslTls;
    private Integer handshakeSuccessfulCounter;
    private Integer handshakeFailedCounter;
    private Integer connectionRfc7918SecureCounter;
    private Integer connectionInsecureCounter;
    private List<SimulatedClient> simulatedClientList;
    
    public void createHSRes(String host) {
        this.host = host;
        supportsSslTls = null;
        handshakeSuccessfulCounter = null;
        handshakeFailedCounter = null;
        connectionRfc7918SecureCounter = null;
        connectionInsecureCounter = null;
        simulatedClientList = null;
    }

    public String getHost() {
        return host;
    }

    public Boolean getSupportsSslTls() {
        return supportsSslTls;
    }

    public Integer getHandshakeSuccessfulCounter() {
        return handshakeSuccessfulCounter;
    }

    public Integer getHandshakeFailedCounter() {
        return handshakeFailedCounter;
    }

    public Integer getConnectionRfc7918SecureCounter() {
        return connectionRfc7918SecureCounter;
    }

    public Integer getConnectionInsecureCounter() {
        return connectionInsecureCounter;
    }

    public List<SimulatedClient> getSimulatedClientList() {
        return simulatedClientList;
    }

    public void setSupportsSslTls(Boolean supportsSslTls) {
        this.supportsSslTls = supportsSslTls;
    }

    public void setHandshakeSuccessfulCounter(Integer handshakeSuccessfulCounter) {
        this.handshakeSuccessfulCounter = handshakeSuccessfulCounter;
    }

    public void setHandshakeFailedCounter(Integer handshakeFailedCounter) {
        this.handshakeFailedCounter = handshakeFailedCounter;
    }

    public void setConnectionRfc7918SecureCounter(Integer connectionRfc7918SecureCounter) {
        this.connectionRfc7918SecureCounter = connectionRfc7918SecureCounter;
    }

    public void setConnectionInsecureCounter(Integer connectionInsecureCounter) {
        this.connectionInsecureCounter = connectionInsecureCounter;
    }

    public void setSimulatedClientList(List<SimulatedClient> simulatedClientList) {
        this.simulatedClientList = simulatedClientList;
    }
}
