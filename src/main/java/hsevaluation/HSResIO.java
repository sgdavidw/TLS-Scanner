/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

import de.rub.nds.modifiablevariable.util.XMLPrettyPrinter;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.TlsClientConfig;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.TlsClientConfigIO;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXB;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactoryConfigurationException;
import org.xml.sax.SAXException;

public class HSResIO {
    
    private HSResIO() {
    }
    
    public static void write(HSRes hSRes, File file) {
        OutputStream os = null;
        try {
            os = new FileOutputStream(file);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(HSRes.class.getName()).log(Level.SEVERE, null, ex);
        }
        ByteArrayOutputStream tempStream = new ByteArrayOutputStream();
        JAXB.marshal(hSRes, tempStream);
        try {
            os.write(XMLPrettyPrinter.prettyPrintXML(new String(tempStream.toByteArray())).getBytes());
        } catch (IOException | TransformerException | XPathExpressionException | XPathFactoryConfigurationException | ParserConfigurationException | SAXException ex) {
            throw new RuntimeException("Could not format XML");
        }
    }

    public static HSRes read(File file) {
        HSRes hSRes = JAXB.unmarshal(file, HSRes.class);
        return hSRes;
    }
}
