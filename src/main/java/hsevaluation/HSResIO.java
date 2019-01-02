/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import javax.xml.bind.JAXB;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

public class HSResIO {

    private HSResIO() {
    }

    private static JAXBContext contextSingleton;

    private static synchronized JAXBContext getJAXBContext() throws JAXBException, IOException {
        if (contextSingleton == null) {
            contextSingleton = JAXBContext.newInstance(HSRes.class);
        }
        return contextSingleton;
    }

    public static void write(HSRes hSRes, File file) {
        try (OutputStream os = new FileOutputStream(file)) {
            JAXBContext context = getJAXBContext();
            Marshaller m = context.createMarshaller();
            m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            m.marshal(hSRes, os);
        } catch (JAXBException | IOException ex) {
            throw new RuntimeException("Could not format XML " + ex);
        }
    }

    public static HSRes read(File file) {
        HSRes hSRes = JAXB.unmarshal(file, HSRes.class);
        return hSRes;
    }
}
